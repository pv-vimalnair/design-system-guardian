"""Trusted-time freshness assessment and sealed current-snapshot task pinning."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import read_canonical_json, sha256_digest
from .clock import utc_now as _utc_now
from .contracts import ResolutionStatus
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path
from .policy import verify_policy_anchor
from .project_binding import ProjectBindingError, capture_project_binding, verify_bound_project
from .profile import load_profile
from .snapshot import SnapshotValidationError, classify_source_state, load_snapshot
from .storage import exclusive_write_json, profile_transaction_lock


class PreflightError(ValueError):
    """Raised when a task cannot establish an unambiguous immutable pin."""


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PIN_KEYS = {
    "schemaVersion", "runId", "profileId", "profileDigest", "snapshotId",
    "catalogDigest", "policyDigest", "sourceCut", "sourceState", "degraded",
    "approvalSequence", "approvalDigest", "projectBinding", "authoritySeal",
}


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise PreflightError("runId must be an exact safe identifier of at most 128 characters.")
    return run_id


def _pin_path(home: Path, profile_id: str, run_id: str) -> Path:
    _validate_run_id(run_id)
    path = GuardianPaths(home).profile(profile_id) / "runs" / run_id / "pin.json"
    try:
        return assert_guardian_storage_path(home, path)
    except (PathIntegrityError, ValueError) as error:
        raise PreflightError(f"Task pin path is unsafe: {error}") from error


def _unsigned_pin(pin: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in pin.items() if key != "authoritySeal"}


def _rule_snapshot_status(snapshot: dict[str, Any]) -> ResolutionStatus | None:
    if snapshot.get("schemaVersion") != 2:
        return None
    rule_evidence = snapshot.get("ruleEvidence")
    rule_validation = snapshot.get("ruleValidation")
    if not isinstance(rule_evidence, dict) or not isinstance(rule_validation, dict):
        raise PreflightError("Rule-snapshot evidence is missing or malformed.")
    if (
        rule_evidence.get("captureAttempted") is not True
        or rule_evidence.get("sourceComplete") is not True
    ):
        return ResolutionStatus.SOURCE_INCOMPLETE
    validation_status = rule_validation.get("status")
    if validation_status == ResolutionStatus.ALLOWED.value:
        return None
    if validation_status == ResolutionStatus.NOT_ASSESSED.value:
        return ResolutionStatus.NOT_ASSESSED
    if validation_status == ResolutionStatus.INVALID.value:
        raise PreflightError("The current signed rule snapshot contains invalid rule evidence.")
    raise PreflightError("The current signed rule snapshot has an unsupported validation status.")


def _read_verified_pin(home: Path, profile_id: str, run_id: str) -> dict[str, Any]:
    path = _pin_path(home, profile_id, run_id)
    try:
        pin = read_canonical_json(path)
        assert_guardian_storage_path(home, path)
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise PreflightError(f"Task pin cannot be read safely and canonically: {error}") from error
    if not isinstance(pin, dict) or set(pin) != _PIN_KEYS:
        raise PreflightError("Task pin has unknown or missing fields.")
    if pin.get("runId") != run_id or pin.get("profileId") != profile_id:
        raise PreflightError("Task pin identity conflicts with its isolated path.")
    try:
        verify_authority_seal(
            home,
            f"run-pin:{profile_id}:{run_id}",
            _unsigned_pin(pin),
            pin["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise PreflightError(f"Task pin authority seal is invalid: {error}") from error
    return pin


def load_run_pin(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
    policy_digest: str | None = None,
) -> dict[str, Any]:
    """Load one exact pin and bind it to current trust, profile, and sealed snapshot."""

    normalized_home = home.expanduser().absolute()
    actual_policy_digest = verify_policy_anchor(normalized_home)
    if policy_digest is not None and policy_digest != actual_policy_digest:
        raise PreflightError("Requested policy digest differs from the immutable trust anchor.")
    pin = _read_verified_pin(normalized_home, profile_id, run_id)
    try:
        verify_bound_project(pin["projectBinding"])
    except ProjectBindingError as error:
        raise PreflightError(f"Task pin intended project is invalid: {error}") from error
    profile = load_profile(normalized_home, profile_id)
    snapshot = load_snapshot(normalized_home, profile_id, pin.get("snapshotId"))
    checks = {
        "profileId": profile_id,
        "profileDigest": sha256_digest(profile),
        "snapshotId": snapshot["snapshotId"],
        "catalogDigest": snapshot["catalogDigest"],
        "policyDigest": actual_policy_digest,
        "sourceCut": snapshot["sourceCut"],
        "approvalSequence": snapshot["approvalSequence"],
        "approvalDigest": snapshot["approvalDigest"],
    }
    for field, expected in checks.items():
        if pin.get(field) != expected:
            raise PreflightError(f"Task pin {field} does not match its verified profile or snapshot.")
    return {"pin": copy.deepcopy(pin), "profile": profile, "snapshot": snapshot}


def preflight_snapshot(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
    policy_digest: str,
    project_root: Path,
) -> dict[str, Any]:
    """Atomically assess and pin only the authority-sealed current observation."""

    normalized_home = home.expanduser().absolute()
    _validate_run_id(run_id)
    actual_policy_digest = verify_policy_anchor(normalized_home)
    if policy_digest != actual_policy_digest:
        raise PreflightError("Preflight policy digest differs from the immutable trust anchor.")
    try:
        project_binding = capture_project_binding(project_root)
    except ProjectBindingError as error:
        raise PreflightError(f"Intended project cannot be bound: {error}") from error
    try:
        with profile_transaction_lock(normalized_home, profile_id):
            profile = load_profile(normalized_home, profile_id)
            snapshot = load_snapshot(normalized_home, profile_id)
            expected_profile_digest = sha256_digest(profile)
            if snapshot.get("profileDigest") != expected_profile_digest:
                raise PreflightError(
                    "Snapshot was created for a different profile revision; refresh is required."
                )
            try:
                freshness = classify_source_state(snapshot, now=_utc_now())
            except SnapshotValidationError as error:
                raise PreflightError(str(error)) from error
            source_state = freshness["state"]
            rule_status = _rule_snapshot_status(snapshot)
            if rule_status is ResolutionStatus.SOURCE_INCOMPLETE:
                source_state = "source_incomplete"
                freshness = {
                    "state": "source_incomplete",
                    "ageHours": None,
                    "degraded": False,
                }
            status = rule_status or {
                "fresh": ResolutionStatus.ALLOWED,
                "offline_grace": ResolutionStatus.ALLOWED,
                "stale": ResolutionStatus.STALE,
                "source_unavailable": ResolutionStatus.SOURCE_UNAVAILABLE,
                "source_incomplete": ResolutionStatus.SOURCE_INCOMPLETE,
            }[source_state]
            pin_eligible = status is ResolutionStatus.ALLOWED
            pin: dict[str, Any] | None = None
            if pin_eligible:
                unsigned = {
                    "schemaVersion": 1,
                    "runId": run_id,
                    "profileId": profile_id,
                    "profileDigest": expected_profile_digest,
                    "snapshotId": snapshot["snapshotId"],
                    "catalogDigest": snapshot["catalogDigest"],
                    "policyDigest": actual_policy_digest,
                    "sourceCut": copy.deepcopy(snapshot["sourceCut"]),
                    "sourceState": source_state,
                    "degraded": source_state == "offline_grace",
                    "approvalSequence": snapshot["approvalSequence"],
                    "approvalDigest": snapshot["approvalDigest"],
                    "projectBinding": copy.deepcopy(project_binding),
                }
                pin = {
                    **unsigned,
                    "authoritySeal": authority_seal(
                        normalized_home, f"run-pin:{profile_id}:{run_id}", unsigned
                    ),
                }
                path = _pin_path(normalized_home, profile_id, run_id)
                try:
                    exclusive_write_json(normalized_home, path, pin)
                except FileExistsError:
                    existing = _read_verified_pin(normalized_home, profile_id, run_id)
                    if existing != pin:
                        raise PreflightError(
                            "A run ID cannot be repinned to another profile, policy, or snapshot."
                        )
                assert_guardian_storage_path(normalized_home, path)
            return {
                "schemaVersion": 1,
                "status": status.value,
                "profileId": profile_id,
                "profileDigest": expected_profile_digest,
                "snapshotId": snapshot["snapshotId"],
                "approvalSequence": snapshot["approvalSequence"],
                "policyDigest": actual_policy_digest,
                "projectBinding": copy.deepcopy(project_binding),
                "sourceState": source_state,
                "freshnessEvidence": freshness,
                "degraded": source_state == "offline_grace",
                "pin": pin,
                "pinCreated": pin is not None,
            }
    except PreflightError:
        raise
    except (AuthorityIntegrityError, PathIntegrityError, OSError, TimeoutError, ValueError) as error:
        raise PreflightError(f"Task pin transaction failed closed: {error}") from error

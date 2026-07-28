"""Immutable, externally approved and authority-sealed catalog snapshots."""

from __future__ import annotations

import copy
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import read_canonical_json, sha256_digest
from .catalog_authority import CatalogAuthorityError, verify_catalog_approval
from .clock import utc_now as _utc_now
from .dtcg import DtcgValidationError, resolve_token_document
from .dtcg_resolver import materialize_resolver_tokens
from .paths import (
    GuardianPaths,
    PathIntegrityError,
    assert_guardian_storage_path,
    is_link_or_reparse,
)
from .policy import verify_policy_anchor
from .profile import ProfileValidationError, load_profile, validate_profile
from .storage import contained_atomic_write_json, exclusive_write_json, profile_transaction_lock


class SnapshotValidationError(ValueError):
    """Raised when catalog evidence cannot form a trustworthy snapshot."""


_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SEQUENCE_RECORD_NAME = re.compile(r"^([1-9][0-9]*)\.json$")
_SNAPSHOT_RECORD_NAME = re.compile(r"^([0-9a-f]{64})\.json$")
_MAX_APPROVAL_SEQUENCE = (1 << 63) - 1
_CATALOG_KEYS = {
    "schemaVersion", "profileId", "createdAt", "refreshAttemptedAt",
    "lastSuccessfulRefreshAt", "sourceAvailable", "sourceComplete",
    "sourceEvidence", "sourceCut", "tokenProvenance", "tokens",
    "resolver", "resolverContext", "registry", "approvalAttestation",
}
_SOURCE_CUT_KEYS = {
    "figmaFiles", "catalogDigest", "codeConnectParseDigest",
    "repositoryCommit", "componentCatalogBuild",
}
_SOURCE_EVIDENCE_KEYS = {"refreshAttempted", "figmaVariables"}
_FIGMA_VARIABLE_EVIDENCE_KEYS = {"used", "valuesPresent", "modesPresent"}
_SNAPSHOT_KEYS = {
    "schemaVersion", "profileId", "profileDigest", "policyDigest", "snapshotId",
    "authoritySeal", "assessedAt", "createdAt", "refreshAttemptedAt",
    "lastSuccessfulRefreshAt", "sourceState", "sourceAvailable", "sourceComplete",
    "sourceEvidence", "freshnessEvidence", "immutable", "sourceCut",
    "tokenProvenance", "tokens", "resolver", "registry", "catalogDigest",
    "catalogEvidence", "approvalSequence", "approvalKeyId", "approvalIssuedAt",
    "approvalDigest",
}
_CURRENT_POINTER_KEYS = {
    "schemaVersion", "profileId", "profileDigest", "policyDigest", "snapshotId",
    "catalogDigest", "approvalSequence", "approvalDigest", "authoritySeal",
}
_SEQUENCE_RECORD_KEYS = {
    "schemaVersion", "profileId", "profileDigest", "policyDigest", "snapshotId",
    "catalogDigest", "approvalSequence", "approvalDigest", "authoritySeal",
}


def _has_rule_namespace_evidence(home: Path, profile_id: str) -> bool:
    paths = GuardianPaths(home)
    candidates = (
        paths.rule_snapshots(profile_id),
        paths.rule_approval_sequences(profile_id),
        paths.current_rule_snapshot(profile_id),
    )
    evidence_present = False
    for candidate in candidates:
        try:
            assert_guardian_storage_path(home, candidate)
            candidate.lstat()
            evidence_present = True
        except FileNotFoundError:
            continue
        except (OSError, PathIntegrityError):
            evidence_present = True
    if not evidence_present:
        return False
    from .rule_activation import has_rule_namespace_evidence

    if not has_rule_namespace_evidence(home, profile_id):
        raise SnapshotValidationError(
            "Rule-snapshot namespace evidence changed during inspection."
        )
    return True


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise SnapshotValidationError(f"{field} must be an ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SnapshotValidationError(f"{field} is not a valid ISO 8601 timestamp.") from error
    if parsed.tzinfo is None:
        raise SnapshotValidationError(f"{field} must include an explicit UTC offset.")
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_now(now: datetime) -> datetime:
    if now.tzinfo is None:
        raise SnapshotValidationError("Freshness assessment time must include a timezone.")
    return now.astimezone(timezone.utc)


def _figma_variables_complete(source_evidence: Any) -> bool:
    if not isinstance(source_evidence, dict):
        return False
    variables = source_evidence.get("figmaVariables")
    if variables is None:
        return True
    if not isinstance(variables, dict):
        return False
    if variables.get("used") is not True:
        return True
    return variables.get("valuesPresent") is True and variables.get("modesPresent") is True


def _validate_refresh_order(source: dict[str, Any], *, now: datetime) -> None:
    assessment = _normalize_now(now)
    available = {
        field: _timestamp(source[field], field)
        for field in ("lastSuccessfulRefreshAt", "refreshAttemptedAt", "createdAt")
        if field in source
    }
    for field, value in available.items():
        if value > assessment:
            raise SnapshotValidationError(f"{field} cannot be in the future.")
    if set(available) == {"lastSuccessfulRefreshAt", "refreshAttemptedAt", "createdAt"}:
        if not (
            available["lastSuccessfulRefreshAt"]
            <= available["refreshAttemptedAt"]
            <= available["createdAt"]
        ):
            raise SnapshotValidationError(
                "Refresh evidence must satisfy lastSuccessfulRefreshAt <= refreshAttemptedAt <= createdAt."
            )


def classify_source_state(source: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    """Classify availability, completeness, offline grace, and hard staleness."""

    assessment = _normalize_now(now)
    _validate_refresh_order(source, now=assessment)
    complete = source.get("sourceComplete") is True and _figma_variables_complete(
        source.get("sourceEvidence", {})
    )
    if not complete:
        return {"state": "source_incomplete", "ageHours": None, "degraded": False}
    successful_at = _timestamp(source.get("lastSuccessfulRefreshAt"), "lastSuccessfulRefreshAt")
    age_hours = (assessment - successful_at).total_seconds() / 3600
    if age_hours >= 168:
        state = "stale"
    elif source.get("sourceAvailable") is not True:
        state = "offline_grace" if age_hours <= 72 else "source_unavailable"
    else:
        state = "fresh"
    return {
        "state": state,
        "ageHours": round(age_hours, 6),
        "degraded": state == "offline_grace",
        "dailyRefreshDue": age_hours >= 24,
    }


def _validate_source_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotValidationError("sourceEvidence must be an object.")
    if set(value) - _SOURCE_EVIDENCE_KEYS or "refreshAttempted" not in value:
        raise SnapshotValidationError("sourceEvidence contains unknown fields or omits refreshAttempted.")
    if value.get("refreshAttempted") is not True:
        raise SnapshotValidationError("Every ingestion must record a completed refresh attempt.")
    variables = value.get("figmaVariables")
    if variables is not None:
        if not isinstance(variables, dict) or set(variables) != _FIGMA_VARIABLE_EVIDENCE_KEYS:
            raise SnapshotValidationError("figmaVariables evidence must use the exact completeness fields.")
        if any(not isinstance(variables[field], bool) for field in _FIGMA_VARIABLE_EVIDENCE_KEYS):
            raise SnapshotValidationError("figmaVariables completeness fields must be booleans.")
    return copy.deepcopy(value)


def _validate_catalog_shape(catalog: Any, profile_id: str) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise SnapshotValidationError("Catalog input must be a JSON object.")
    unknown = set(catalog) - _CATALOG_KEYS
    required = _CATALOG_KEYS - {"resolver", "resolverContext"}
    missing = required - set(catalog)
    if unknown:
        raise SnapshotValidationError(f"Unknown catalog properties: {sorted(unknown)!r}.")
    if missing:
        raise SnapshotValidationError(f"Missing catalog properties: {sorted(missing)!r}.")
    if catalog.get("schemaVersion") != 1:
        raise SnapshotValidationError("Catalog schemaVersion must be exactly 1.")
    if catalog.get("profileId") != profile_id:
        raise SnapshotValidationError("Catalog profileId conflicts with the selected isolated profile.")
    for field in ("sourceAvailable", "sourceComplete"):
        if not isinstance(catalog.get(field), bool):
            raise SnapshotValidationError(f"{field} must be a boolean.")
    for field in ("createdAt", "refreshAttemptedAt", "lastSuccessfulRefreshAt"):
        _timestamp(catalog.get(field), field)
    _validate_source_evidence(catalog.get("sourceEvidence"))
    return copy.deepcopy(catalog)


def _validate_source_cut(profile: dict[str, Any], source_cut: Any) -> dict[str, Any]:
    if not isinstance(source_cut, dict):
        raise SnapshotValidationError("sourceCut must be an object.")
    unknown = set(source_cut) - _SOURCE_CUT_KEYS
    missing = (_SOURCE_CUT_KEYS - {"catalogDigest"}) - set(source_cut)
    if unknown or missing:
        raise SnapshotValidationError(
            f"sourceCut has unknown {sorted(unknown)!r} or missing {sorted(missing)!r} properties."
        )
    figma_files = source_cut.get("figmaFiles")
    if not isinstance(figma_files, list):
        raise SnapshotValidationError("sourceCut.figmaFiles must be an array.")
    allowed = {
        item["fileKey"]
        for field in ("allowlistedLibraryFiles", "allowlistedWorkingFiles")
        for item in profile["figma"].get(field, [])
    }
    seen: set[str] = set()
    normalized_files: list[dict[str, str]] = []
    for item in figma_files:
        if not isinstance(item, dict) or set(item) != {"fileKey", "version"}:
            raise SnapshotValidationError("Each source-cut Figma file needs exact fileKey and version fields.")
        file_key, version = item.get("fileKey"), item.get("version")
        if file_key not in allowed or file_key in seen:
            raise SnapshotValidationError(
                "Source-cut Figma files must be unique and explicitly authorized by the profile."
            )
        if not isinstance(version, str) or not version:
            raise SnapshotValidationError("Source-cut Figma versions must be non-empty exact strings.")
        seen.add(file_key)
        normalized_files.append({"fileKey": file_key, "version": version})
    if seen != allowed:
        raise SnapshotValidationError(
            "A complete source cut must version every profile-authorized library and working file."
        )
    digest = source_cut.get("codeConnectParseDigest")
    if digest is not None and (not isinstance(digest, str) or not _HEX_64.fullmatch(digest)):
        raise SnapshotValidationError("codeConnectParseDigest must be null or a lowercase SHA-256 digest.")
    for field in ("repositoryCommit", "componentCatalogBuild"):
        value = source_cut.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise SnapshotValidationError(f"{field} must be null or a non-empty exact version string.")
    claimed_catalog_digest = source_cut.get("catalogDigest")
    if claimed_catalog_digest is not None and (
        not isinstance(claimed_catalog_digest, str) or not _HEX_64.fullmatch(claimed_catalog_digest)
    ):
        raise SnapshotValidationError("sourceCut.catalogDigest must be a lowercase SHA-256 digest when supplied.")
    return {
        "figmaFiles": sorted(normalized_files, key=lambda item: item["fileKey"]),
        "catalogDigest": claimed_catalog_digest,
        "codeConnectParseDigest": digest,
        "repositoryCommit": source_cut.get("repositoryCommit"),
        "componentCatalogBuild": source_cut.get("componentCatalogBuild"),
    }


def _validate_token_provenance(value: Any) -> dict[str, Any]:
    required = {"approval", "source", "sourceVersion", "published"}
    if not isinstance(value, dict) or set(value) != required:
        raise SnapshotValidationError("tokenProvenance must contain only the canonical approval fields.")
    if value.get("approval") != "explicit" or value.get("published") is not True:
        raise SnapshotValidationError("Tokens require explicit published catalog approval.")
    if any(not isinstance(value.get(field), str) or not value[field] for field in ("source", "sourceVersion")):
        raise SnapshotValidationError("Token provenance source and sourceVersion must be non-empty strings.")
    return copy.deepcopy(value)


def _catalog_payload(snapshot_like: dict[str, Any]) -> dict[str, Any]:
    return {
        "tokenProvenance": snapshot_like["tokenProvenance"],
        "tokens": snapshot_like["tokens"],
        "resolver": snapshot_like.get("resolver"),
        "registry": snapshot_like["registry"],
    }


def _snapshot_digest(snapshot: dict[str, Any]) -> str:
    content = {
        key: value for key, value in snapshot.items() if key not in {"snapshotId", "authoritySeal"}
    }
    return sha256_digest(content)


def _build_unsigned_snapshot(
    home: Path,
    profile: dict[str, Any],
    catalog_document: Any,
    *,
    assessed_at: datetime,
    policy_digest: str,
) -> dict[str, Any]:
    catalog = _validate_catalog_shape(catalog_document, profile["profileId"])
    assessment = _normalize_now(assessed_at)
    try:
        approval = verify_catalog_approval(
            home,
            policy_digest=policy_digest,
            profile=profile,
            catalog=catalog,
            now=assessment,
        )
    except CatalogAuthorityError as error:
        raise SnapshotValidationError(f"Catalog approval is invalid: {error}") from error
    _validate_refresh_order(catalog, now=assessment)
    source_cut = _validate_source_cut(profile, catalog["sourceCut"])
    token_provenance = _validate_token_provenance(catalog["tokenProvenance"])
    try:
        resolver = None
        if "resolver" in catalog:
            materialized = materialize_resolver_tokens(
                catalog["tokens"], catalog["resolver"], catalog.get("resolverContext")
            )
            tokens = materialized["tokens"]
            resolver = {
                "document": copy.deepcopy(catalog["resolver"]),
                "evidence": materialized["evidence"],
            }
        else:
            tokens = resolve_token_document(catalog["tokens"])
    except DtcgValidationError as error:
        raise SnapshotValidationError(str(error)) from error
    for token in tokens.values():
        token["approved"] = True
        token["provenance"] = copy.deepcopy(token_provenance)

    # A freshly selected personal working file can legitimately contain no
    # component instances yet. Enterprise catalogs retain the historical
    # exact-instance requirement.
    from .personal_selection import load_personal_profile_authority

    personal_authority = load_personal_profile_authority(
        home,
        profile["profileId"],
        missing_ok=True,
    )
    if (
        personal_authority is not None
        and personal_authority.get("profileDigest") != sha256_digest(profile)
    ):
        raise SnapshotValidationError(
            "Personal profile authority differs from the installed profile."
        )
    registry = validate_registry(
        profile,
        source_cut,
        catalog["registry"],
        allow_unused_working_files=personal_authority is not None,
    )
    approved_code_mapping_present = any(
        mapping.get("approved") is True
        for plural in ("components", "icons")
        for asset in registry[plural]
        for mapping in asset["codeMappings"]
    )
    code_provenance_complete = (
        source_cut["codeConnectParseDigest"] is not None
        and source_cut["repositoryCommit"] is not None
    )
    state = classify_source_state(catalog, now=assessment)
    if approved_code_mapping_present and not code_provenance_complete:
        state = {"state": "source_incomplete", "ageHours": None, "degraded": False}
    effective_complete = state["state"] != "source_incomplete"
    base: dict[str, Any] = {
        "schemaVersion": 1,
        "profileId": profile["profileId"],
        "profileDigest": sha256_digest(profile),
        "policyDigest": policy_digest,
        "assessedAt": _timestamp_text(assessment),
        "createdAt": _timestamp_text(_timestamp(catalog["createdAt"], "createdAt")),
        "refreshAttemptedAt": _timestamp_text(
            _timestamp(catalog["refreshAttemptedAt"], "refreshAttemptedAt")
        ),
        "lastSuccessfulRefreshAt": _timestamp_text(
            _timestamp(catalog["lastSuccessfulRefreshAt"], "lastSuccessfulRefreshAt")
        ),
        "sourceState": state["state"],
        "sourceAvailable": catalog["sourceAvailable"],
        "sourceComplete": effective_complete,
        "sourceEvidence": _validate_source_evidence(catalog["sourceEvidence"]),
        "freshnessEvidence": state,
        "immutable": True,
        "sourceCut": source_cut,
        "tokenProvenance": token_provenance,
        "tokens": tokens,
        "resolver": resolver,
        "registry": registry,
        "catalogEvidence": copy.deepcopy(catalog),
        "approvalSequence": approval["sequence"],
        "approvalKeyId": approval["keyId"],
        "approvalIssuedAt": _timestamp_text(
            _timestamp(approval["issuedAt"], "approvalAttestation.issuedAt")
        ),
        "approvalDigest": sha256_digest(catalog),
    }
    catalog_digest = sha256_digest(_catalog_payload(base))
    claimed_digest = source_cut.get("catalogDigest")
    if claimed_digest is not None and claimed_digest != catalog_digest:
        raise SnapshotValidationError("Claimed source-cut catalogDigest does not match canonical catalog content.")
    base["catalogDigest"] = catalog_digest
    base["sourceCut"]["catalogDigest"] = catalog_digest
    snapshot = {**base, "snapshotId": ""}
    snapshot["snapshotId"] = _snapshot_digest(snapshot)
    return snapshot


def _seal_snapshot(home: Path, unsigned: dict[str, Any]) -> dict[str, Any]:
    return {**copy.deepcopy(unsigned), "authoritySeal": authority_seal(home, "snapshot", unsigned)}


def _pointer_or_sequence_unsigned(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "profileId": snapshot["profileId"],
        "profileDigest": snapshot["profileDigest"],
        "policyDigest": snapshot["policyDigest"],
        "snapshotId": snapshot["snapshotId"],
        "catalogDigest": snapshot["catalogDigest"],
        "approvalSequence": snapshot["approvalSequence"],
        "approvalDigest": snapshot["approvalDigest"],
    }


def _current_pointer(home: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    unsigned = _pointer_or_sequence_unsigned(snapshot)
    return {
        **unsigned,
        "authoritySeal": authority_seal(home, f"current-snapshot:{snapshot['profileId']}", unsigned),
    }


def _sequence_record(home: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    unsigned = _pointer_or_sequence_unsigned(snapshot)
    purpose = f"approval-sequence:{snapshot['profileId']}:{snapshot['approvalSequence']}"
    return {**unsigned, "authoritySeal": authority_seal(home, purpose, unsigned)}


def _read_exact_sealed_record(
    home: Path,
    path: Path,
    *,
    keys: set[str],
    purpose: str,
    missing_ok: bool,
) -> dict[str, Any] | None:
    try:
        assert_guardian_storage_path(home, path)
        value = read_canonical_json(path)
        assert_guardian_storage_path(home, path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SnapshotValidationError(f"Required sealed record is missing: {path.name}.")
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise SnapshotValidationError(f"Sealed snapshot record cannot be read safely: {error}") from error
    if not isinstance(value, dict) or set(value) != keys:
        raise SnapshotValidationError("Sealed snapshot record has an invalid exact contract.")
    unsigned = {key: item for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, purpose, unsigned, value["authoritySeal"])
    except AuthorityIntegrityError as error:
        raise SnapshotValidationError(f"Sealed snapshot record authority is invalid: {error}") from error
    return value


def _read_current_pointer(
    home: Path,
    profile_id: str,
    policy_digest: str,
    *,
    missing_ok: bool,
) -> dict[str, Any] | None:
    pointer = _read_exact_sealed_record(
        home,
        GuardianPaths(home).profile(profile_id) / "current-snapshot.json",
        keys=_CURRENT_POINTER_KEYS,
        purpose=f"current-snapshot:{profile_id}",
        missing_ok=missing_ok,
    )
    if pointer is None:
        return None
    if pointer.get("profileId") != profile_id or pointer.get("policyDigest") != policy_digest:
        raise SnapshotValidationError("Current snapshot pin crosses profile or immutable policy identity.")
    if not isinstance(pointer.get("snapshotId"), str) or not _HEX_64.fullmatch(pointer["snapshotId"]):
        raise SnapshotValidationError("Current snapshot pin has an invalid snapshot identity.")
    sequence = pointer.get("approvalSequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise SnapshotValidationError("Current snapshot pin has an invalid approval sequence.")
    if not isinstance(pointer.get("approvalDigest"), str) or not _HEX_64.fullmatch(pointer["approvalDigest"]):
        raise SnapshotValidationError("Current snapshot pin has an invalid approval digest.")
    return pointer


def _read_sequence_record(
    home: Path,
    profile_id: str,
    profile_digest: str,
    policy_digest: str,
    sequence: int,
) -> dict[str, Any] | None:
    path = GuardianPaths(home).profile(profile_id) / "approval-sequences" / f"{sequence}.json"
    record = _read_exact_sealed_record(
        home,
        path,
        keys=_SEQUENCE_RECORD_KEYS,
        purpose=f"approval-sequence:{profile_id}:{sequence}",
        missing_ok=True,
    )
    if record is None:
        return None
    if (
        record.get("schemaVersion") != 1
        or record.get("profileId") != profile_id
        or record.get("profileDigest") != profile_digest
        or record.get("policyDigest") != policy_digest
        or record.get("approvalSequence") != sequence
    ):
        raise SnapshotValidationError("Approval-sequence record crosses trust or profile identity.")
    for field in ("snapshotId", "catalogDigest", "approvalDigest"):
        if not isinstance(record.get(field), str) or not _HEX_64.fullmatch(record[field]):
            raise SnapshotValidationError(
                f"Approval-sequence record has an invalid {field}."
            )
    return record


def _read_sequence_history(
    home: Path,
    profile_id: str,
    profile_digest: str,
    policy_digest: str,
) -> dict[int, dict[str, Any]]:
    directory = GuardianPaths(home).profile(profile_id) / "approval-sequences"
    try:
        assert_guardian_storage_path(home, directory)
        if is_link_or_reparse(directory):
            raise SnapshotValidationError(
                "Approval-sequence history may not be redirected."
            )
        metadata = directory.lstat()
    except FileNotFoundError:
        return {}
    except (OSError, PathIntegrityError) as error:
        raise SnapshotValidationError(
            f"Approval-sequence history cannot be inspected safely: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotValidationError("Approval-sequence history must be a directory.")

    records: dict[int, dict[str, Any]] = {}
    try:
        entries = list(directory.iterdir())
        assert_guardian_storage_path(home, directory)
    except (OSError, PathIntegrityError) as error:
        raise SnapshotValidationError(
            f"Approval-sequence history cannot be enumerated safely: {error}"
        ) from error
    if not entries:
        raise SnapshotValidationError(
            "Approval-sequence history directory is empty or was truncated."
        )
    for entry in entries:
        try:
            assert_guardian_storage_path(home, entry)
            if is_link_or_reparse(entry):
                raise SnapshotValidationError(
                    "Approval-sequence history contains redirected evidence."
                )
            entry_metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise SnapshotValidationError(
                f"Approval-sequence history entry cannot be inspected safely: {error}"
            ) from error
        match = _SEQUENCE_RECORD_NAME.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(entry_metadata.st_mode):
            raise SnapshotValidationError(
                "Approval-sequence history contains an unexpected entry."
            )
        sequence = int(match.group(1))
        if sequence > _MAX_APPROVAL_SEQUENCE:
            raise SnapshotValidationError(
                "Approval-sequence history exceeds the supported monotonic range."
            )
        record = _read_sequence_record(
            home,
            profile_id,
            profile_digest,
            policy_digest,
            sequence,
        )
        if record is None:
            raise SnapshotValidationError(
                "Approval-sequence history changed during verification."
            )
        records[sequence] = record
    return records


def _load_snapshot_document(
    home: Path,
    profile: dict[str, Any],
    policy_digest: str,
    snapshot_id: str,
) -> dict[str, Any]:
    profile_id = profile["profileId"]
    if not isinstance(snapshot_id, str) or not _HEX_64.fullmatch(snapshot_id):
        raise SnapshotValidationError("snapshotId must be an exact lowercase SHA-256 digest.")
    snapshot_path = GuardianPaths(home).snapshots(profile_id) / f"{snapshot_id}.json"
    try:
        assert_guardian_storage_path(home, snapshot_path)
        snapshot = read_canonical_json(snapshot_path)
        assert_guardian_storage_path(home, snapshot_path)
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise SnapshotValidationError(
            f"Immutable snapshot cannot be read safely and canonically: {error}"
        ) from error
    if not isinstance(snapshot, dict) or set(snapshot) != _SNAPSHOT_KEYS:
        raise SnapshotValidationError(
            "Snapshot has unknown, missing, or non-canonical top-level fields."
        )
    unsigned = {
        key: value for key, value in snapshot.items() if key != "authoritySeal"
    }
    try:
        verify_authority_seal(home, "snapshot", unsigned, snapshot["authoritySeal"])
    except AuthorityIntegrityError as error:
        raise SnapshotValidationError(
            f"Snapshot authority seal is invalid: {error}"
        ) from error
    if snapshot.get("profileId") != profile_id:
        raise SnapshotValidationError(
            "Snapshot profile identity conflicts with its isolated path."
        )
    if snapshot.get("profileDigest") != sha256_digest(profile):
        raise SnapshotValidationError(
            "Snapshot profile digest differs from the installed profile revision."
        )
    if snapshot.get("policyDigest") != policy_digest:
        raise SnapshotValidationError(
            "Snapshot immutable policy digest differs from the trust anchor."
        )
    if snapshot.get("immutable") is not True or snapshot.get("snapshotId") != snapshot_id:
        raise SnapshotValidationError("Snapshot immutable identity metadata is invalid.")
    if _snapshot_digest(snapshot) != snapshot_id:
        raise SnapshotValidationError(
            "Snapshot content digest does not match its immutable ID."
        )
    rebuilt = _build_unsigned_snapshot(
        home,
        profile,
        snapshot["catalogEvidence"],
        assessed_at=_timestamp(snapshot["assessedAt"], "assessedAt"),
        policy_digest=policy_digest,
    )
    if rebuilt != unsigned:
        raise SnapshotValidationError(
            "Snapshot normalized evidence does not reconstruct exactly from original catalog evidence."
        )
    return copy.deepcopy(snapshot)


def _read_snapshot_history(
    home: Path,
    profile: dict[str, Any],
    policy_digest: str,
) -> dict[int, dict[str, Any]]:
    profile_id = profile["profileId"]
    directory = GuardianPaths(home).snapshots(profile_id)
    try:
        assert_guardian_storage_path(home, directory)
        if is_link_or_reparse(directory):
            raise SnapshotValidationError(
                "Immutable snapshot history may not be redirected."
            )
        metadata = directory.lstat()
    except FileNotFoundError:
        return {}
    except (OSError, PathIntegrityError) as error:
        raise SnapshotValidationError(
            f"Immutable snapshot history cannot be inspected safely: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotValidationError(
            "Immutable snapshot history must be a directory."
        )
    try:
        entries = list(directory.iterdir())
        assert_guardian_storage_path(home, directory)
    except (OSError, PathIntegrityError) as error:
        raise SnapshotValidationError(
            f"Immutable snapshot history cannot be enumerated safely: {error}"
        ) from error
    if not entries:
        raise SnapshotValidationError(
            "Immutable snapshot history directory is empty or was truncated."
        )

    records: dict[int, dict[str, Any]] = {}
    for entry in entries:
        try:
            assert_guardian_storage_path(home, entry)
            if is_link_or_reparse(entry):
                raise SnapshotValidationError(
                    "Immutable snapshot history contains redirected evidence."
                )
            entry_metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise SnapshotValidationError(
                f"Immutable snapshot history entry cannot be inspected safely: {error}"
            ) from error
        match = _SNAPSHOT_RECORD_NAME.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(entry_metadata.st_mode):
            raise SnapshotValidationError(
                "Immutable snapshot history contains an unexpected entry."
            )
        snapshot = _load_snapshot_document(
            home,
            profile,
            policy_digest,
            match.group(1),
        )
        sequence = snapshot.get("approvalSequence")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 1
            or sequence > _MAX_APPROVAL_SEQUENCE
        ):
            raise SnapshotValidationError(
                "Immutable snapshot has an invalid approval sequence."
            )
        record = _pointer_or_sequence_unsigned(snapshot)
        if sequence in records:
            raise SnapshotValidationError(
                "Immutable snapshot history reuses one approval sequence."
            )
        records[sequence] = record
    return records


def _verify_catalog_high_water(
    home: Path,
    profile: dict[str, Any],
    policy_digest: str,
    current: dict[str, Any] | None,
    *,
    recover_missing_current: bool = True,
) -> dict[str, Any] | None:
    profile_id = profile["profileId"]
    sequence_history = _read_sequence_history(
        home,
        profile_id,
        sha256_digest(profile),
        policy_digest,
    )
    snapshot_history = _read_snapshot_history(home, profile, policy_digest)
    if set(sequence_history) != set(snapshot_history):
        raise SnapshotValidationError(
            "Catalog approval history is truncated or mismatched between immutable snapshots and sealed sequence records."
        )
    retained_sequences = sorted(snapshot_history)
    if retained_sequences and retained_sequences != list(
        range(retained_sequences[0], retained_sequences[-1] + 1)
    ):
        raise SnapshotValidationError(
            "Catalog approval history contains a noncontiguous sequence gap."
        )
    for sequence, sequence_record in sequence_history.items():
        unsigned_record = {
            key: value
            for key, value in sequence_record.items()
            if key != "authoritySeal"
        }
        if unsigned_record != snapshot_history[sequence]:
            raise SnapshotValidationError(
                "Catalog approval history conflicts at a retained sequence."
            )
    if not snapshot_history:
        if current is not None:
            raise SnapshotValidationError(
                "Current snapshot exists without retained catalog approval history."
            )
        return None

    highest_sequence = max(snapshot_history)
    highest = snapshot_history[highest_sequence]
    pointer_path = GuardianPaths(home).profile(profile_id) / "current-snapshot.json"
    if current is None:
        if not recover_missing_current:
            raise SnapshotValidationError(
                "Current snapshot pointer is missing; read-only verification will not repair it."
            )
        recovered = _current_pointer(home, highest)
        contained_atomic_write_json(home, pointer_path, recovered)
        assert_guardian_storage_path(home, pointer_path)
        return recovered
    current_unsigned = {
        key: value for key, value in current.items() if key != "authoritySeal"
    }
    if current["approvalSequence"] != highest_sequence:
        raise SnapshotValidationError(
            "Current snapshot pointer is replayed and differs from the retained approval high-water."
        )
    if current_unsigned != highest:
        raise SnapshotValidationError(
            "Current snapshot conflicts with the retained approval high-water."
        )
    return current


def _store_snapshot_once(home: Path, snapshot: dict[str, Any]) -> None:
    path = GuardianPaths(home).snapshots(snapshot["profileId"]) / f"{snapshot['snapshotId']}.json"
    assert_guardian_storage_path(home, path)
    try:
        exclusive_write_json(home, path, snapshot)
    except FileExistsError:
        existing = load_snapshot(home, snapshot["profileId"], snapshot["snapshotId"])
        if existing != snapshot:
            raise SnapshotValidationError(
                "Immutable snapshot ID collision or existing snapshot mutation detected."
            )
    assert_guardian_storage_path(home, path)


def ingest_snapshot(home: Path, profile_document: Any, catalog_document: Any) -> dict[str, Any]:
    """Verify external approval, seal, store, and monotonically promote one snapshot."""

    if isinstance(catalog_document, dict) and catalog_document.get("schemaVersion") == 2:
        from .rule_activation import ingest_rule_snapshot

        return ingest_rule_snapshot(home, profile_document, catalog_document)
    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    profile = validate_profile(profile_document)
    if _has_rule_namespace_evidence(normalized_home, profile["profileId"]):
        raise SnapshotValidationError(
            "Catalog v1 cannot advance after rule-snapshot activation evidence exists."
        )
    installed_profile = load_profile(normalized_home, profile["profileId"])
    if installed_profile != profile:
        raise SnapshotValidationError("Snapshot ingestion profile differs from the installed isolated profile.")
    unsigned = _build_unsigned_snapshot(
        normalized_home,
        profile,
        catalog_document,
        assessed_at=_utc_now(),
        policy_digest=policy_digest,
    )
    snapshot = _seal_snapshot(normalized_home, unsigned)
    paths = GuardianPaths(normalized_home)
    profile_id = profile["profileId"]
    sequence = snapshot["approvalSequence"]
    try:
        with profile_transaction_lock(normalized_home, profile_id):
            if _has_rule_namespace_evidence(normalized_home, profile_id):
                raise SnapshotValidationError(
                    "Catalog v1 cannot advance after rule-snapshot activation evidence exists."
                )
            current = _read_current_pointer(
                normalized_home, profile_id, policy_digest, missing_ok=True
            )
            current = _verify_catalog_high_water(
                normalized_home,
                profile,
                policy_digest,
                current,
            )
            if (
                current is not None
                and sequence > current["approvalSequence"] + 1
            ):
                raise SnapshotValidationError(
                    "Catalog approval sequence must remain contiguous after the retained high-water."
                )
            if current is not None and sequence < current["approvalSequence"]:
                raise SnapshotValidationError(
                    "Catalog approval sequence is lower than the sealed current sequence."
                )
            if current is not None and sequence == current["approvalSequence"]:
                if snapshot["approvalDigest"] != current["approvalDigest"]:
                    raise SnapshotValidationError(
                        "The current approval sequence was reused for different catalog content."
                    )
                return load_snapshot(normalized_home, profile_id, current["snapshotId"])

            record = _read_sequence_record(
                normalized_home,
                profile_id,
                snapshot["profileDigest"],
                policy_digest,
                sequence,
            )
            if record is not None:
                if record["approvalDigest"] != snapshot["approvalDigest"]:
                    raise SnapshotValidationError(
                        "The approval sequence was previously sealed for different catalog content."
                    )
                existing = load_snapshot(normalized_home, profile_id, record["snapshotId"])
                pointer_path = paths.profile(profile_id) / "current-snapshot.json"
                contained_atomic_write_json(
                    normalized_home,
                    pointer_path,
                    _current_pointer(normalized_home, existing),
                )
                return copy.deepcopy(existing)

            _store_snapshot_once(normalized_home, snapshot)
            sequence_path = paths.profile(profile_id) / "approval-sequences" / f"{sequence}.json"
            exclusive_write_json(
                normalized_home,
                sequence_path,
                _sequence_record(normalized_home, snapshot),
            )
            pointer_path = paths.profile(profile_id) / "current-snapshot.json"
            contained_atomic_write_json(
                normalized_home,
                pointer_path,
                _current_pointer(normalized_home, snapshot),
            )
            assert_guardian_storage_path(normalized_home, pointer_path)
    except SnapshotValidationError:
        raise
    except (AuthorityIntegrityError, PathIntegrityError, OSError, TimeoutError, ValueError) as error:
        raise SnapshotValidationError(f"Snapshot storage integrity failure: {error}") from error
    return copy.deepcopy(snapshot)




def load_snapshot(
    home: Path,
    profile_id: str,
    snapshot_id: str | None = None,
    *,
    recover_missing_current: bool = True,
) -> dict[str, Any]:
    """Verify HMAC authority and reconstruct externally approved normalized evidence."""

    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    try:
        profile = load_profile(normalized_home, profile_id)
    except ProfileValidationError as error:
        raise SnapshotValidationError(f"Selected snapshot profile cannot be loaded: {error}") from error
    if _has_rule_namespace_evidence(normalized_home, profile_id):
        from .rule_activation import load_rule_snapshot

        rule_snapshot = load_rule_snapshot(
            normalized_home,
            profile_id,
            snapshot_id,
        )
        if rule_snapshot is not None:
            return rule_snapshot
        if snapshot_id is None:
            raise SnapshotValidationError(
                "Rule-snapshot activation evidence exists without a valid current v2 snapshot."
            )
    current = _read_current_pointer(
        normalized_home,
        profile_id,
        policy_digest,
        missing_ok=True,
    )
    current = _verify_catalog_high_water(
        normalized_home,
        profile,
        policy_digest,
        current,
        recover_missing_current=recover_missing_current,
    )
    if snapshot_id is None:
        if current is None:
            raise SnapshotValidationError("Required current snapshot record is missing.")
        snapshot_id = str(current["snapshotId"])
    return _load_snapshot_document(normalized_home, profile, policy_digest, snapshot_id)


def validate_registry(
    profile: dict[str, Any],
    source_cut: dict[str, Any],
    registry_document: Any,
    *,
    allow_unused_working_files: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Validate published identities and exact remote instances in signed working files."""

    if not isinstance(registry_document, dict) or set(registry_document) != {"components", "icons"}:
        raise SnapshotValidationError("registry must contain separate components and icons arrays.")
    source_versions = {item["fileKey"]: item["version"] for item in source_cut["figmaFiles"]}
    library_keys = {item["fileKey"] for item in profile["figma"]["allowlistedLibraryFiles"]}
    allowed_versions = {file_key: source_versions[file_key] for file_key in library_keys}
    working_keys = {
        item["fileKey"] for item in profile["figma"].get("allowlistedWorkingFiles", [])
    }
    working_versions = {file_key: source_versions[file_key] for file_key in working_keys}
    used_working_files: set[str] = set()
    working_locator_owners: dict[tuple[str, str, str], tuple[str, str]] = {}
    normalized: dict[str, list[dict[str, Any]]] = {"components": [], "icons": []}
    for plural, kind in (("components", "component"), ("icons", "icon")):
        items = registry_document[plural]
        if not isinstance(items, list):
            raise SnapshotValidationError(f"registry.{plural} must be an array.")
        seen: set[str] = set()
        for item in items:
            normalized[plural].append(
                _validate_asset(
                    item,
                    kind=kind,
                    allowed_versions=allowed_versions,
                    working_versions=working_versions,
                    working_locator_owners=working_locator_owners,
                    used_working_files=used_working_files,
                    seen=seen,
                )
            )
        normalized[plural].sort(key=lambda item: item["identity"])
    if not allow_unused_working_files and used_working_files != set(working_versions):
        raise SnapshotValidationError(
            "Every non-library Figma file in the source cut must have an exact working-instance binding."
        )
    return normalized


def _validate_asset(
    item: Any,
    *,
    kind: str,
    allowed_versions: dict[str, str],
    working_versions: dict[str, str],
    working_locator_owners: dict[tuple[str, str, str], tuple[str, str]],
    used_working_files: set[str],
    seen: set[str],
) -> dict[str, Any]:
    keys = {"identity", "status", "sourceVersion", "figma", "variants", "properties", "codeMappings"}
    if not isinstance(item, dict) or set(item) - (keys | {"workingFileInstances"}) or not keys.issubset(item):
        raise SnapshotValidationError(f"Every {kind} record must contain only the canonical registry fields.")
    identity = item.get("identity")
    if not isinstance(identity, str) or not identity or identity in seen:
        raise SnapshotValidationError(f"{kind} identities must be non-empty and unique within their registry.")
    seen.add(identity)
    status = item.get("status")
    if status not in {"approved", "deprecated", "candidate", "removed"}:
        raise SnapshotValidationError(f"Invalid {kind} registry status for {identity!r}.")
    figma = item.get("figma")
    if not isinstance(figma, dict) or set(figma) != {"fileKey", "nodeId", "assetKey", "published"}:
        raise SnapshotValidationError(f"{kind} {identity!r} needs exact Figma identity fields.")
    file_key = figma.get("fileKey")
    if file_key not in allowed_versions:
        raise SnapshotValidationError(f"{kind} {identity!r} comes from a non-allowlisted Figma file.")
    if any(not isinstance(figma.get(field), str) or not figma[field] for field in ("nodeId", "assetKey")):
        raise SnapshotValidationError(f"{kind} {identity!r} has an incomplete stable Figma identity.")
    if not isinstance(figma.get("published"), bool):
        raise SnapshotValidationError(f"{kind} {identity!r} published flag must be a boolean.")
    source_version = item.get("sourceVersion")
    if source_version != allowed_versions[file_key]:
        raise SnapshotValidationError(f"{kind} {identity!r} sourceVersion is not the pinned Figma version.")
    approved = status in {"approved", "deprecated"}
    if approved and figma.get("published") is not True:
        raise SnapshotValidationError(f"Unpublished/local Figma {kind} {identity!r} cannot be approved.")
    variants = item.get("variants")
    if not isinstance(variants, list) or any(
        not isinstance(value, str) or not value for value in variants
    ):
        raise SnapshotValidationError(f"{kind} {identity!r} variants must be exact strings.")
    if len(set(variants)) != len(variants):
        raise SnapshotValidationError(f"{kind} {identity!r} variants must be unique.")
    properties = item.get("properties")
    if not isinstance(properties, dict):
        raise SnapshotValidationError(f"{kind} {identity!r} properties must be an object.")
    for name, values in properties.items():
        if not isinstance(name, str) or not name or not isinstance(values, list) or not values:
            raise SnapshotValidationError(f"{kind} {identity!r} has an invalid property registry.")
        if any(not isinstance(value, str) or not value for value in values):
            raise SnapshotValidationError(f"{kind} {identity!r} property values must be exact strings.")
        if len(set(values)) != len(values):
            raise SnapshotValidationError(f"{kind} {identity!r} property values must be unique.")
    mappings = item.get("codeMappings")
    if not isinstance(mappings, list):
        raise SnapshotValidationError(f"{kind} {identity!r} codeMappings must be an array.")
    normalized_mappings: list[dict[str, Any]] = []
    mapping_keys: set[tuple[str, str]] = set()
    for mapping in mappings:
        required = {"framework", "symbol", "approved", "inferred", "sourceDigest"}
        if not isinstance(mapping, dict) or set(mapping) != required:
            raise SnapshotValidationError(f"{kind} {identity!r} has a malformed code mapping.")
        framework, symbol = mapping.get("framework"), mapping.get("symbol")
        if not isinstance(framework, str) or not framework or not isinstance(symbol, str) or not symbol:
            raise SnapshotValidationError(f"{kind} {identity!r} code mappings need exact framework and symbol.")
        key = (framework, symbol)
        if key in mapping_keys:
            raise SnapshotValidationError(f"{kind} {identity!r} has duplicate exact code mappings.")
        mapping_keys.add(key)
        if not isinstance(mapping.get("approved"), bool) or not isinstance(mapping.get("inferred"), bool):
            raise SnapshotValidationError(f"{kind} {identity!r} mapping flags must be booleans.")
        if mapping["inferred"] and mapping["approved"]:
            raise SnapshotValidationError("A newly inferred Code Connect mapping cannot be approved automatically.")
        if not isinstance(mapping.get("sourceDigest"), str) or not _HEX_64.fullmatch(mapping["sourceDigest"]):
            raise SnapshotValidationError(f"{kind} {identity!r} code mapping needs an exact source digest.")
        normalized_mappings.append(copy.deepcopy(mapping))
    normalized = {
        "kind": kind,
        "identity": identity,
        "status": status,
        "approved": approved,
        "deprecated": status == "deprecated",
        "sourceVersion": source_version,
        "figma": copy.deepcopy(figma),
        "variants": sorted(variants),
        "properties": {name: sorted(values) for name, values in sorted(properties.items())},
        "codeMappings": sorted(normalized_mappings, key=lambda value: (value["framework"], value["symbol"])),
        "provenance": {
            "fileKey": file_key,
            "nodeId": figma["nodeId"],
            "assetKey": figma["assetKey"],
            "published": figma["published"],
            "sourceVersion": source_version,
        },
    }
    if "workingFileInstances" in item:
        normalized["workingFileInstances"] = _validate_working_file_instances(
            item["workingFileInstances"],
            kind=kind,
            identity=identity,
            canonical_asset_key=figma["assetKey"],
            approved_variants=variants,
            approved_properties=properties,
            working_versions=working_versions,
            working_locator_owners=working_locator_owners,
            used_working_files=used_working_files,
        )
    return normalized


def _validate_working_file_instances(
    value: Any,
    *,
    kind: str,
    identity: str,
    canonical_asset_key: str,
    approved_variants: list[str],
    approved_properties: dict[str, list[str]],
    working_versions: dict[str, str],
    working_locator_owners: dict[tuple[str, str, str], tuple[str, str]],
    used_working_files: set[str],
) -> list[dict[str, Any]]:
    fields = {
        "fileKey", "nodeId", "sourceVersion", "nodeType", "canonicalAssetKey",
        "remote", "variant", "properties", "unapprovedOverrideFields",
    }
    if not isinstance(value, list) or not value:
        raise SnapshotValidationError(
            f"{kind} {identity!r} workingFileInstances must be a non-empty array when supplied."
        )
    normalized: list[dict[str, Any]] = []
    for binding in value:
        if not isinstance(binding, dict) or set(binding) != fields:
            raise SnapshotValidationError(
                f"{kind} {identity!r} has malformed working-instance evidence."
            )
        file_key = binding.get("fileKey")
        node_id = binding.get("nodeId")
        source_version = binding.get("sourceVersion")
        if any(not isinstance(item, str) or not item for item in (file_key, node_id, source_version)):
            raise SnapshotValidationError("Working-instance locators must be exact non-empty strings.")
        if file_key not in working_versions or source_version != working_versions[file_key]:
            raise SnapshotValidationError(
                "Working-instance evidence must use a pinned non-library Figma file version."
            )
        if (
            binding.get("nodeType") != "INSTANCE"
            or binding.get("remote") is not True
            or binding.get("canonicalAssetKey") != canonical_asset_key
        ):
            raise SnapshotValidationError(
                "Working-instance evidence must retain the exact approved remote main-component identity."
            )
        if binding.get("unapprovedOverrideFields") != []:
            raise SnapshotValidationError(
                "Working instances with unapproved visual overrides cannot be approved."
            )
        variant = binding.get("variant")
        if approved_variants:
            if not isinstance(variant, str) or variant not in approved_variants:
                raise SnapshotValidationError("Working-instance variant is not exactly approved.")
        elif variant is not None:
            raise SnapshotValidationError("Working-instance variant is not registered.")
        selected_properties = binding.get("properties")
        if not isinstance(selected_properties, dict) or set(selected_properties) != set(approved_properties):
            raise SnapshotValidationError(
                "Working-instance properties must select every registered property exactly."
            )
        for name, selected in selected_properties.items():
            if not isinstance(selected, str) or selected not in approved_properties[name]:
                raise SnapshotValidationError("Working-instance property value is not exactly approved.")
        locator = (file_key, node_id, source_version)
        if locator in working_locator_owners:
            raise SnapshotValidationError(
                "One working-instance locator cannot resolve to multiple or duplicate identities."
            )
        working_locator_owners[locator] = (kind, identity)
        used_working_files.add(file_key)
        normalized.append(copy.deepcopy(binding))
    return sorted(
        normalized,
        key=lambda item: (item["fileKey"], item["nodeId"], item["sourceVersion"]),
    )

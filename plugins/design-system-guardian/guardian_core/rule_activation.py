"""Permission-bound, append-only rule snapshot v2 activation.

This module deliberately keeps profile and snapshot v1 bytes untouched.  The
v2 lineage is a parallel, locally sealed projection of one externally signed
catalog approval sequence.
"""

from __future__ import annotations

import copy
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from . import snapshot as v1_snapshot
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
from .rules import RuleValidationError, validate_rules
from .storage import contained_atomic_write_json, exclusive_write_json, profile_transaction_lock


class RuleActivationError(ValueError):
    """Raised when rule activation evidence cannot be trusted exactly."""


ACTIVE_CAPABILITIES = [
    {"predicate": "forbidden_identity_in_scope", "scope": "compilation_unit"},
    {"predicate": "max_instances_per_scope", "scope": "compilation_unit"},
]
EVALUATOR_ID = "guardian-flutter-usage-rules-v1"
NAMESPACE_TARGET = "rule-snapshots-v2"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_SEQUENCE_FILE = re.compile(r"^([1-9][0-9]*)\.json$")
_MAX_SEQUENCE = (1 << 63) - 1

_CATALOG_KEYS = {
    "schemaVersion",
    "profileId",
    "createdAt",
    "refreshAttemptedAt",
    "lastSuccessfulRefreshAt",
    "sourceAvailable",
    "sourceComplete",
    "sourceEvidence",
    "sourceCut",
    "tokenProvenance",
    "tokens",
    "resolver",
    "resolverContext",
    "registry",
    "rules",
    "ruleEvidence",
    "approvalAttestation",
}
_CATALOG_REQUIRED = _CATALOG_KEYS - {"resolver", "resolverContext"}
_SNAPSHOT_KEYS = {
    "schemaVersion",
    "profileId",
    "profileDigest",
    "policyDigest",
    "snapshotId",
    "authoritySeal",
    "previousSnapshotId",
    "assessedAt",
    "createdAt",
    "refreshAttemptedAt",
    "lastSuccessfulRefreshAt",
    "sourceState",
    "sourceAvailable",
    "sourceComplete",
    "sourceEvidence",
    "freshnessEvidence",
    "immutable",
    "sourceCut",
    "tokenProvenance",
    "tokens",
    "resolver",
    "registry",
    "rules",
    "rulesDigest",
    "ruleEvidence",
    "ruleValidation",
    "activatedCapabilities",
    "activationEvaluatorId",
    "firstActivationPermissionDigest",
    "catalogDigest",
    "catalogEvidence",
    "approvalSequence",
    "approvalKeyId",
    "approvalIssuedAt",
    "approvalDigest",
}
_LINK_KEYS = {
    "schemaVersion",
    "profileId",
    "profileDigest",
    "policyDigest",
    "snapshotId",
    "previousSnapshotId",
    "catalogDigest",
    "rulesDigest",
    "approvalSequence",
    "approvalDigest",
    "firstActivationPermissionDigest",
    "authoritySeal",
}
_PERMISSION_BINDING_KEYS = {
    "schemaVersion",
    "policyDigest",
    "profileId",
    "profileDigest",
    "baseSnapshotId",
    "baseCatalogDigest",
    "candidateCatalogDocumentDigest",
    "candidateCatalogDigest",
    "candidateRulesDigest",
    "candidateApprovalSequence",
    "catalogAuthorityKeyId",
    "namespaceTarget",
    "targetSchemaVersion",
    "evaluatorId",
    "activatedCapabilities",
}


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise RuleActivationError(f"{field} must be an exact lowercase SHA-256 digest.")
    return value


def _sequence(value: Any, field: str = "approvalSequence") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_SEQUENCE
    ):
        raise RuleActivationError(
            f"{field} must be an integer from 1 through {_MAX_SEQUENCE}."
        )
    return value


def _catalog_shape(catalog: Any, profile_id: str) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise RuleActivationError("Catalog v2 must be an object.")
    unknown = set(catalog) - _CATALOG_KEYS
    missing = _CATALOG_REQUIRED - set(catalog)
    if unknown or missing:
        raise RuleActivationError(
            f"Catalog v2 has unknown {sorted(unknown)!r} or missing {sorted(missing)!r} fields."
        )
    if catalog.get("schemaVersion") != 2:
        raise RuleActivationError("Catalog schemaVersion must be exactly 2 for rule activation.")
    if catalog.get("profileId") != profile_id:
        raise RuleActivationError("Catalog profileId conflicts with the selected profile.")
    for field in ("sourceAvailable", "sourceComplete"):
        if not isinstance(catalog.get(field), bool):
            raise RuleActivationError(f"{field} must be a boolean.")
    for field in ("createdAt", "refreshAttemptedAt", "lastSuccessfulRefreshAt"):
        v1_snapshot._timestamp(catalog.get(field), field)
    v1_snapshot._validate_source_evidence(catalog.get("sourceEvidence"))
    evidence = catalog.get("ruleEvidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"captureAttempted", "sourceComplete"}
        or evidence.get("captureAttempted") is not True
        or not isinstance(evidence.get("sourceComplete"), bool)
    ):
        raise RuleActivationError(
            "ruleEvidence must contain exact captureAttempted=true and boolean sourceComplete."
        )
    rules = catalog.get("rules")
    if not isinstance(rules, list) or len(rules) > 4096:
        raise RuleActivationError("Catalog rules must be an array of at most 4096 rules.")
    if any(not isinstance(rule, dict) for rule in rules):
        raise RuleActivationError("Every catalog rule must be an object.")
    return copy.deepcopy(catalog)


def _known_identities(
    tokens: dict[str, Any], registry: dict[str, list[dict[str, Any]]]
) -> frozenset[str]:
    identities = set(tokens)
    for plural in ("components", "icons"):
        identities.update(item["identity"] for item in registry[plural])
    return frozenset(identities)


def _inactive_rule_reason(rule: dict[str, Any]) -> str | None:
    rule_class = rule.get("class")
    if rule_class == "informative":
        return None
    if rule_class == "judgment":
        return "unsupported_rule_class"
    predicate = rule.get("predicate")
    if not isinstance(predicate, dict):
        raise RuleActivationError("Normalized machine rule has no exact predicate.")
    capability = {
        "predicate": predicate.get("type"),
        "scope": predicate.get("scope"),
    }
    return None if capability in ACTIVE_CAPABILITIES else "unsupported_predicate_scope"


def _rule_validation_projection(
    report: dict[str, Any], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    entries = report.get("entries")
    if not isinstance(entries, list):
        raise RuleActivationError("Rule validation did not produce canonical entries.")
    reason_codes = sorted(
        {
            entry["reasonCode"]
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("reasonCode"), str)
        }
    )
    if not reason_codes:
        reason_codes = ["ok"]
    summary = report.get("summary")
    if not isinstance(summary, dict) or set(summary) != {
        "ok",
        "warnings",
        "errors",
        "notAssessed",
    }:
        raise RuleActivationError("Rule validation summary is malformed.")
    projection = {
        "status": report["status"],
        "summary": copy.deepcopy(summary),
        "reasonCodes": reason_codes,
    }
    inactive_reasons = [
        reason
        for rule in rules
        for reason in [_inactive_rule_reason(rule)]
        if reason is not None
    ]
    if inactive_reasons:
        inactive_count = len(inactive_reasons)
        if projection["summary"]["ok"] < inactive_count:
            raise RuleActivationError(
                "Rule validation cannot reconcile inactive evaluator coverage."
            )
        projection["summary"]["ok"] -= inactive_count
        projection["summary"]["notAssessed"] += inactive_count
        if projection["status"] != "invalid":
            projection["status"] = "not_assessed"
        reasons = set(projection["reasonCodes"])
        if projection["summary"]["ok"] == 0:
            reasons.discard("ok")
        reasons.update(inactive_reasons)
        projection["reasonCodes"] = sorted(reasons)
    return projection


def _snapshot_digest(snapshot: dict[str, Any]) -> str:
    return sha256_digest(
        {
            key: value
            for key, value in snapshot.items()
            if key not in {"snapshotId", "authoritySeal"}
        }
    )


def _build_unsigned_snapshot(
    home: Path,
    profile: dict[str, Any],
    catalog_document: Any,
    *,
    assessed_at: datetime,
    policy_digest: str,
    previous_snapshot_id: str,
    first_permission_digest: str,
) -> dict[str, Any]:
    catalog = _catalog_shape(catalog_document, profile["profileId"])
    previous_snapshot_id = _digest(previous_snapshot_id, "previousSnapshotId")
    first_permission_digest = _digest(
        first_permission_digest, "firstActivationPermissionDigest"
    )
    assessment = v1_snapshot._normalize_now(assessed_at)
    try:
        approval = verify_catalog_approval(
            home,
            policy_digest=policy_digest,
            profile=profile,
            catalog=catalog,
            now=assessment,
        )
    except CatalogAuthorityError as error:
        raise RuleActivationError(f"Catalog v2 approval is invalid: {error}") from error

    v1_snapshot._validate_refresh_order(catalog, now=assessment)
    source_cut = v1_snapshot._validate_source_cut(profile, catalog["sourceCut"])
    token_provenance = v1_snapshot._validate_token_provenance(
        catalog["tokenProvenance"]
    )
    try:
        resolver = None
        if "resolver" in catalog:
            materialized = materialize_resolver_tokens(
                catalog["tokens"],
                catalog["resolver"],
                catalog.get("resolverContext"),
            )
            tokens = materialized["tokens"]
            resolver = {
                "document": copy.deepcopy(catalog["resolver"]),
                "evidence": materialized["evidence"],
            }
        else:
            tokens = resolve_token_document(catalog["tokens"])
    except DtcgValidationError as error:
        raise RuleActivationError(str(error)) from error
    for token in tokens.values():
        token["approved"] = True
        token["provenance"] = copy.deepcopy(token_provenance)

    registry = v1_snapshot.validate_registry(profile, source_cut, catalog["registry"])
    try:
        rule_result = validate_rules(
            catalog["rules"],
            known_identities=_known_identities(tokens, registry),
            source_type="artifact",
        )
    except RuleValidationError as error:
        raise RuleActivationError(str(error)) from error
    rules = copy.deepcopy(rule_result["rules"])
    rule_validation = _rule_validation_projection(rule_result["report"], rules)
    rule_evidence = copy.deepcopy(catalog["ruleEvidence"])

    state = v1_snapshot.classify_source_state(catalog, now=assessment)
    approved_mapping_present = any(
        mapping.get("approved") is True
        for plural in ("components", "icons")
        for asset in registry[plural]
        for mapping in asset["codeMappings"]
    )
    code_provenance_complete = (
        source_cut["codeConnectParseDigest"] is not None
        and source_cut["repositoryCommit"] is not None
    )
    if approved_mapping_present and not code_provenance_complete:
        state = {"state": "source_incomplete", "ageHours": None, "degraded": False}
    if rule_evidence["sourceComplete"] is not True:
        state = {"state": "source_incomplete", "ageHours": None, "degraded": False}
    effective_complete = state["state"] != "source_incomplete"

    rules_digest = sha256_digest(rules)
    catalog_digest_payload = {
        "tokenProvenance": token_provenance,
        "tokens": tokens,
        "resolver": resolver,
        "registry": registry,
        "rules": rules,
        "ruleEvidence": rule_evidence,
    }
    catalog_digest = sha256_digest(catalog_digest_payload)
    claimed_digest = source_cut.get("catalogDigest")
    if claimed_digest is not None and claimed_digest != catalog_digest:
        raise RuleActivationError(
            "Claimed source-cut catalogDigest does not cover canonical v2 catalog content."
        )
    source_cut["catalogDigest"] = catalog_digest

    base: dict[str, Any] = {
        "schemaVersion": 2,
        "profileId": profile["profileId"],
        "profileDigest": sha256_digest(profile),
        "policyDigest": policy_digest,
        "previousSnapshotId": previous_snapshot_id,
        "assessedAt": v1_snapshot._timestamp_text(assessment),
        "createdAt": v1_snapshot._timestamp_text(
            v1_snapshot._timestamp(catalog["createdAt"], "createdAt")
        ),
        "refreshAttemptedAt": v1_snapshot._timestamp_text(
            v1_snapshot._timestamp(catalog["refreshAttemptedAt"], "refreshAttemptedAt")
        ),
        "lastSuccessfulRefreshAt": v1_snapshot._timestamp_text(
            v1_snapshot._timestamp(
                catalog["lastSuccessfulRefreshAt"], "lastSuccessfulRefreshAt"
            )
        ),
        "sourceState": state["state"],
        "sourceAvailable": catalog["sourceAvailable"],
        "sourceComplete": effective_complete,
        "sourceEvidence": v1_snapshot._validate_source_evidence(
            catalog["sourceEvidence"]
        ),
        "freshnessEvidence": state,
        "immutable": True,
        "sourceCut": source_cut,
        "tokenProvenance": token_provenance,
        "tokens": tokens,
        "resolver": resolver,
        "registry": registry,
        "rules": rules,
        "rulesDigest": rules_digest,
        "ruleEvidence": rule_evidence,
        "ruleValidation": rule_validation,
        "activatedCapabilities": copy.deepcopy(ACTIVE_CAPABILITIES),
        "activationEvaluatorId": EVALUATOR_ID,
        "firstActivationPermissionDigest": first_permission_digest,
        "catalogDigest": catalog_digest,
        "catalogEvidence": copy.deepcopy(catalog),
        "approvalSequence": approval["sequence"],
        "approvalKeyId": approval["keyId"],
        "approvalIssuedAt": v1_snapshot._timestamp_text(
            v1_snapshot._timestamp(
                approval["issuedAt"], "approvalAttestation.issuedAt"
            )
        ),
        "approvalDigest": sha256_digest(catalog),
    }
    snapshot = {**base, "snapshotId": ""}
    snapshot["snapshotId"] = _snapshot_digest(snapshot)
    return snapshot


def _seal_snapshot(home: Path, unsigned: dict[str, Any]) -> dict[str, Any]:
    return {
        **copy.deepcopy(unsigned),
        "authoritySeal": authority_seal(home, "rule-snapshot:v2", unsigned),
    }


def _link_unsigned(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "profileId": snapshot["profileId"],
        "profileDigest": snapshot["profileDigest"],
        "policyDigest": snapshot["policyDigest"],
        "snapshotId": snapshot["snapshotId"],
        "previousSnapshotId": snapshot["previousSnapshotId"],
        "catalogDigest": snapshot["catalogDigest"],
        "rulesDigest": snapshot["rulesDigest"],
        "approvalSequence": snapshot["approvalSequence"],
        "approvalDigest": snapshot["approvalDigest"],
        "firstActivationPermissionDigest": snapshot[
            "firstActivationPermissionDigest"
        ],
    }


def _sequence_record(home: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    unsigned = _link_unsigned(snapshot)
    purpose = (
        f"rule-approval-sequence:{snapshot['profileId']}:{snapshot['approvalSequence']}"
    )
    return {**unsigned, "authoritySeal": authority_seal(home, purpose, unsigned)}


def _current_pointer(home: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    unsigned = _link_unsigned(snapshot)
    purpose = f"current-rule-snapshot:{snapshot['profileId']}"
    return {**unsigned, "authoritySeal": authority_seal(home, purpose, unsigned)}


def _read_link(
    home: Path,
    path: Path,
    *,
    purpose: str,
    missing_ok: bool,
) -> dict[str, Any] | None:
    try:
        assert_guardian_storage_path(home, path)
        if is_link_or_reparse(path):
            raise RuleActivationError("Rule activation evidence may not be redirected.")
        value = read_canonical_json(path)
        metadata = path.lstat()
        assert_guardian_storage_path(home, path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise RuleActivationError(f"Required v2 record is missing: {path.name}.")
    except RuleActivationError:
        raise
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise RuleActivationError(f"V2 record cannot be read safely: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise RuleActivationError("V2 record must be a regular file.")
    if not isinstance(value, dict) or set(value) != _LINK_KEYS:
        raise RuleActivationError("V2 record has an invalid exact contract.")
    unsigned = {key: item for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(home, purpose, unsigned, value["authoritySeal"])
    except AuthorityIntegrityError as error:
        raise RuleActivationError(f"V2 record authority is invalid: {error}") from error
    return value


def _load_document(
    home: Path,
    profile: dict[str, Any],
    policy_digest: str,
    snapshot_id: str,
) -> dict[str, Any]:
    _digest(snapshot_id, "snapshotId")
    path = GuardianPaths(home).rule_snapshots(profile["profileId"]) / f"{snapshot_id}.json"
    try:
        assert_guardian_storage_path(home, path)
        if is_link_or_reparse(path):
            raise RuleActivationError("Rule snapshot may not be redirected.")
        snapshot = read_canonical_json(path)
        metadata = path.lstat()
        assert_guardian_storage_path(home, path)
    except RuleActivationError:
        raise
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise RuleActivationError(f"Rule snapshot cannot be read safely: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise RuleActivationError("Rule snapshot must be a regular file.")
    if not isinstance(snapshot, dict) or set(snapshot) != _SNAPSHOT_KEYS:
        raise RuleActivationError("Rule snapshot has unknown or missing fields.")
    unsigned = {key: value for key, value in snapshot.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(
            home, "rule-snapshot:v2", unsigned, snapshot["authoritySeal"]
        )
    except AuthorityIntegrityError as error:
        raise RuleActivationError(f"Rule snapshot authority is invalid: {error}") from error
    if snapshot.get("schemaVersion") != 2 or snapshot.get("immutable") is not True:
        raise RuleActivationError("Rule snapshot version or immutability marker is invalid.")
    if snapshot.get("snapshotId") != snapshot_id or _snapshot_digest(snapshot) != snapshot_id:
        raise RuleActivationError("Rule snapshot content digest is invalid.")
    if snapshot.get("profileId") != profile["profileId"]:
        raise RuleActivationError("Rule snapshot profile is cross-contaminated.")
    if snapshot.get("profileDigest") != sha256_digest(profile):
        raise RuleActivationError("Rule snapshot profile digest changed.")
    if snapshot.get("policyDigest") != policy_digest:
        raise RuleActivationError("Rule snapshot policy digest changed.")
    rebuilt = _build_unsigned_snapshot(
        home,
        profile,
        snapshot["catalogEvidence"],
        assessed_at=v1_snapshot._timestamp(snapshot["assessedAt"], "assessedAt"),
        policy_digest=policy_digest,
        previous_snapshot_id=snapshot["previousSnapshotId"],
        first_permission_digest=snapshot["firstActivationPermissionDigest"],
    )
    if rebuilt != unsigned:
        raise RuleActivationError(
            "Rule snapshot does not reconstruct exactly from signed catalog evidence."
        )
    return copy.deepcopy(snapshot)


def _directory_entries(home: Path, directory: Path, *, kind: str) -> list[Path]:
    try:
        assert_guardian_storage_path(home, directory)
        if is_link_or_reparse(directory):
            raise RuleActivationError(f"{kind} history may not be redirected.")
        metadata = directory.lstat()
        entries = list(directory.iterdir())
        assert_guardian_storage_path(home, directory)
    except RuleActivationError:
        raise
    except (OSError, PathIntegrityError) as error:
        raise RuleActivationError(f"{kind} history cannot be inspected: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or not entries:
        raise RuleActivationError(f"{kind} history is missing, empty, or not a directory.")
    return entries


def has_rule_namespace_evidence(home: Path, profile_id: str) -> bool:
    """Return whether any v2 namespace path exists, without treating partial as absent."""

    normalized_home = home.expanduser().absolute()
    paths = GuardianPaths(normalized_home)
    candidates = (
        paths.rule_snapshots(profile_id),
        paths.rule_approval_sequences(profile_id),
        paths.current_rule_snapshot(profile_id),
    )
    try:
        for path in candidates:
            assert_guardian_storage_path(normalized_home, path)
            if path.exists() or is_link_or_reparse(path):
                return True
        return False
    except (OSError, PathIntegrityError) as error:
        raise RuleActivationError(f"Rule namespace cannot be inspected: {error}") from error


def _v1_high_water(
    home: Path, profile: dict[str, Any], policy_digest: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        current = v1_snapshot._read_current_pointer(
            home, profile["profileId"], policy_digest, missing_ok=True
        )
        current = v1_snapshot._verify_catalog_high_water(
            home,
            profile,
            policy_digest,
            current,
            recover_missing_current=False,
        )
    except v1_snapshot.SnapshotValidationError as error:
        raise RuleActivationError(
            f"V1 catalog high-water cannot be verified read-only: {error}"
        ) from error
    if current is None:
        raise RuleActivationError("Rule activation requires an existing v1 catalog snapshot.")
    snapshot = v1_snapshot._load_snapshot_document(
        home, profile, policy_digest, current["snapshotId"]
    )
    return current, snapshot


def load_rule_snapshot(
    home: Path, profile_id: str, snapshot_id: str | None = None
) -> dict[str, Any] | None:
    """Verify the complete v2 history; return None only for an explicit v1 ID."""

    normalized_home = home.expanduser().absolute()
    if not has_rule_namespace_evidence(normalized_home, profile_id):
        return None
    policy_digest = verify_policy_anchor(normalized_home)
    try:
        profile = load_profile(normalized_home, profile_id)
    except ProfileValidationError as error:
        raise RuleActivationError(f"Rule snapshot profile cannot be loaded: {error}") from error
    v1_current, _ = _v1_high_water(normalized_home, profile, policy_digest)
    paths = GuardianPaths(normalized_home)

    snapshots_by_sequence: dict[int, dict[str, Any]] = {}
    snapshots_by_id: dict[str, dict[str, Any]] = {}
    for entry in _directory_entries(
        normalized_home, paths.rule_snapshots(profile_id), kind="Rule snapshot"
    ):
        try:
            assert_guardian_storage_path(normalized_home, entry)
            metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise RuleActivationError(f"Rule snapshot entry cannot be inspected: {error}") from error
        match = _SNAPSHOT_FILE.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
            raise RuleActivationError("Rule snapshot history contains an unexpected entry.")
        item = _load_document(normalized_home, profile, policy_digest, match.group(1))
        sequence = _sequence(item["approvalSequence"])
        if sequence in snapshots_by_sequence:
            raise RuleActivationError("Rule snapshot history reuses an approval sequence.")
        snapshots_by_sequence[sequence] = item
        snapshots_by_id[item["snapshotId"]] = item

    records: dict[int, dict[str, Any]] = {}
    for entry in _directory_entries(
        normalized_home,
        paths.rule_approval_sequences(profile_id),
        kind="Rule approval-sequence",
    ):
        try:
            assert_guardian_storage_path(normalized_home, entry)
            metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise RuleActivationError(f"Rule sequence entry cannot be inspected: {error}") from error
        match = _SEQUENCE_FILE.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
            raise RuleActivationError("Rule sequence history contains an unexpected entry.")
        sequence = _sequence(int(match.group(1)))
        record = _read_link(
            normalized_home,
            entry,
            purpose=f"rule-approval-sequence:{profile_id}:{sequence}",
            missing_ok=False,
        )
        assert record is not None
        records[sequence] = record

    if set(records) != set(snapshots_by_sequence):
        raise RuleActivationError("Rule snapshot and sequence histories are mismatched.")
    sequences = sorted(snapshots_by_sequence)
    expected_first = _sequence(v1_current["approvalSequence"]) + 1
    if sequences != list(range(expected_first, sequences[-1] + 1)):
        raise RuleActivationError("Rule approval history is not globally contiguous from v1.")
    previous_id = v1_current["snapshotId"]
    first_permission: str | None = None
    for sequence in sequences:
        item = snapshots_by_sequence[sequence]
        if item["previousSnapshotId"] != previous_id:
            raise RuleActivationError("Rule snapshot previousSnapshotId chain is invalid.")
        if first_permission is None:
            first_permission = item["firstActivationPermissionDigest"]
        elif item["firstActivationPermissionDigest"] != first_permission:
            raise RuleActivationError("Rule activation permission lineage changed.")
        record_unsigned = {
            key: value for key, value in records[sequence].items() if key != "authoritySeal"
        }
        if record_unsigned != _link_unsigned(item):
            raise RuleActivationError("Rule sequence record conflicts with its snapshot.")
        previous_id = item["snapshotId"]

    pointer = _read_link(
        normalized_home,
        paths.current_rule_snapshot(profile_id),
        purpose=f"current-rule-snapshot:{profile_id}",
        missing_ok=False,
    )
    assert pointer is not None
    high = snapshots_by_sequence[sequences[-1]]
    pointer_unsigned = {
        key: value for key, value in pointer.items() if key != "authoritySeal"
    }
    if pointer_unsigned != _link_unsigned(high):
        raise RuleActivationError("Current rule snapshot is not the retained v2 high-water.")
    if snapshot_id is None:
        return copy.deepcopy(high)
    if not isinstance(snapshot_id, str) or _HEX_64.fullmatch(snapshot_id) is None:
        raise RuleActivationError("snapshotId must be an exact lowercase SHA-256 digest.")
    found = snapshots_by_id.get(snapshot_id)
    return None if found is None else copy.deepcopy(found)


def _permission_binding(
    *,
    policy_digest: str,
    profile: dict[str, Any],
    base: dict[str, Any],
    catalog: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    attestation = catalog["approvalAttestation"]
    return {
        "schemaVersion": 1,
        "policyDigest": policy_digest,
        "profileId": profile["profileId"],
        "profileDigest": sha256_digest(profile),
        "baseSnapshotId": base["snapshotId"],
        "baseCatalogDigest": base["catalogDigest"],
        "candidateCatalogDocumentDigest": sha256_digest(catalog),
        "candidateCatalogDigest": candidate["catalogDigest"],
        "candidateRulesDigest": candidate["rulesDigest"],
        "candidateApprovalSequence": candidate["approvalSequence"],
        "catalogAuthorityKeyId": attestation["keyId"],
        "namespaceTarget": NAMESPACE_TARGET,
        "targetSchemaVersion": 2,
        "evaluatorId": EVALUATOR_ID,
        "activatedCapabilities": copy.deepcopy(ACTIVE_CAPABILITIES),
    }


def _prepare_first_activation(
    home: Path,
    profile_id: str,
    catalog_document: Any,
    *,
    require_fresh_complete: bool,
    assessed_at: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    policy_digest = verify_policy_anchor(home)
    try:
        profile = load_profile(home, profile_id)
    except ProfileValidationError as error:
        raise RuleActivationError(f"Selected profile cannot be loaded: {error}") from error
    _, base = _v1_high_water(home, profile, policy_digest)
    catalog = _catalog_shape(catalog_document, profile_id)
    candidate = _build_unsigned_snapshot(
        home,
        profile,
        catalog,
        assessed_at=_utc_now() if assessed_at is None else assessed_at,
        policy_digest=policy_digest,
        previous_snapshot_id=base["snapshotId"],
        first_permission_digest="0" * 64,
    )
    if candidate["approvalSequence"] != base["approvalSequence"] + 1:
        raise RuleActivationError(
            "First v2 approval sequence must advance exactly one from the v1 high-water."
        )
    if require_fresh_complete:
        if candidate["sourceState"] != "fresh" or candidate["sourceComplete"] is not True:
            raise RuleActivationError("Rule activation requires a fresh, complete source snapshot.")
        if candidate["ruleEvidence"]["sourceComplete"] is not True:
            raise RuleActivationError("Rule capture is incomplete and cannot be activated.")
        if candidate["ruleValidation"]["status"] == "invalid":
            raise RuleActivationError("Invalid rule evidence cannot be activated.")
    binding = _permission_binding(
        policy_digest=policy_digest,
        profile=profile,
        base=base,
        catalog=catalog,
        candidate=candidate,
    )
    return profile, base, catalog, binding


def preview_rule_activation(
    home: Path, *, profile_id: str, catalog_document: Any
) -> dict[str, Any]:
    """Verify one first activation candidate without writing any state."""

    normalized_home = home.expanduser().absolute()
    if has_rule_namespace_evidence(normalized_home, profile_id):
        raise RuleActivationError(
            "Rule activation evidence already exists; use signed v2 snapshot ingestion."
        )
    _, _, _, binding = _prepare_first_activation(
        normalized_home,
        profile_id,
        catalog_document,
        require_fresh_complete=True,
    )
    return {
        "schemaVersion": 1,
        "status": "permission_required",
        "profileId": profile_id,
        "permissionRequired": True,
        "permissionBinding": binding,
        "localChangesPerformed": False,
        "productionReady": False,
    }


def _validate_bundle(bundle: Any) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not isinstance(bundle, dict) or set(bundle) != {
        "schemaVersion",
        "profileId",
        "catalog",
        "permission",
    }:
        raise RuleActivationError("Activation bundle has an invalid exact contract.")
    if bundle.get("schemaVersion") != 1:
        raise RuleActivationError("Activation bundle schemaVersion must be exactly 1.")
    profile_id = bundle.get("profileId")
    if not isinstance(profile_id, str):
        raise RuleActivationError("Activation bundle profileId is invalid.")
    permission = bundle.get("permission")
    if not isinstance(permission, dict) or set(permission) != _PERMISSION_BINDING_KEYS | {
        "granted"
    }:
        raise RuleActivationError("Activation permission has an invalid exact contract.")
    if permission.get("granted") is not True:
        raise RuleActivationError("Activation permission was not granted.")
    binding = {key: copy.deepcopy(value) for key, value in permission.items() if key != "granted"}
    return profile_id, copy.deepcopy(bundle["catalog"]), binding


def _preflight_first_storage(
    home: Path,
    profile_id: str,
    snapshot: dict[str, Any],
    sequence_record: dict[str, Any],
    pointer: dict[str, Any],
) -> tuple[Path, Path, Path, bool]:
    paths = GuardianPaths(home)
    snapshot_path = paths.rule_snapshots(profile_id) / f"{snapshot['snapshotId']}.json"
    sequence_path = paths.rule_approval_sequences(profile_id) / f"{snapshot['approvalSequence']}.json"
    pointer_path = paths.current_rule_snapshot(profile_id)
    expected = {
        snapshot_path: snapshot,
        sequence_path: sequence_record,
        pointer_path: pointer,
    }
    changed = False
    for directory, allowed in (
        (paths.rule_snapshots(profile_id), {snapshot_path.name}),
        (paths.rule_approval_sequences(profile_id), {sequence_path.name}),
    ):
        assert_guardian_storage_path(home, directory)
        if is_link_or_reparse(directory):
            raise RuleActivationError("Rule activation storage may not be redirected.")
        if directory.exists():
            if not directory.is_dir():
                raise RuleActivationError("Rule activation history path must be a directory.")
            names = {entry.name for entry in directory.iterdir()}
            if names - allowed:
                raise RuleActivationError("Existing rule activation history is divergent.")
    for path, value in expected.items():
        assert_guardian_storage_path(home, path)
        if is_link_or_reparse(path):
            raise RuleActivationError("Rule activation record may not be redirected.")
        if path.exists():
            try:
                existing = read_canonical_json(path)
            except (OSError, ValueError, UnicodeError) as error:
                raise RuleActivationError(f"Existing activation record is invalid: {error}") from error
            if existing != value:
                raise RuleActivationError("Existing activation evidence differs from the permitted candidate.")
        else:
            changed = True
    return snapshot_path, sequence_path, pointer_path, changed


def _recover_partial_first_activation(
    home: Path,
    profile_id: str,
    catalog_document: Any,
    supplied_binding: dict[str, Any],
) -> dict[str, Any]:
    policy_digest = verify_policy_anchor(home)
    try:
        profile = load_profile(home, profile_id)
    except ProfileValidationError as error:
        raise RuleActivationError(f"Selected profile cannot be loaded: {error}") from error
    _, base = _v1_high_water(home, profile, policy_digest)
    catalog = _catalog_shape(catalog_document, profile_id)
    paths = GuardianPaths(home)
    entries = _directory_entries(
        home,
        paths.rule_snapshots(profile_id),
        kind="Partial rule snapshot",
    )
    if len(entries) != 1:
        raise RuleActivationError(
            "Interrupted activation must retain exactly one first rule snapshot."
        )
    entry = entries[0]
    try:
        assert_guardian_storage_path(home, entry)
        metadata = entry.lstat()
    except (OSError, PathIntegrityError) as error:
        raise RuleActivationError(
            f"Partial rule snapshot cannot be inspected: {error}"
        ) from error
    match = _SNAPSHOT_FILE.fullmatch(entry.name)
    if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
        raise RuleActivationError("Interrupted activation contains divergent snapshot evidence.")
    snapshot = _load_document(home, profile, policy_digest, match.group(1))
    if (
        snapshot["approvalSequence"] != base["approvalSequence"] + 1
        or snapshot["previousSnapshotId"] != base["snapshotId"]
    ):
        raise RuleActivationError(
            "Interrupted activation no longer continues the exact v1 high-water."
        )
    if snapshot["catalogEvidence"] != catalog:
        raise RuleActivationError(
            "Interrupted activation catalog differs from the permitted candidate."
        )
    expected_binding = _permission_binding(
        policy_digest=policy_digest,
        profile=profile,
        base=base,
        catalog=catalog,
        candidate=snapshot,
    )
    if (
        supplied_binding != expected_binding
        or snapshot["firstActivationPermissionDigest"]
        != sha256_digest(supplied_binding)
    ):
        raise RuleActivationError(
            "Interrupted activation differs from the exact granted permission."
        )
    current_source_state = v1_snapshot.classify_source_state(
        catalog,
        now=_utc_now(),
    )
    if (
        snapshot["sourceState"] != "fresh"
        or current_source_state["state"] != "fresh"
        or snapshot["sourceComplete"] is not True
        or snapshot["ruleEvidence"]["sourceComplete"] is not True
        or snapshot["ruleValidation"]["status"] == "invalid"
    ):
        raise RuleActivationError(
            "Interrupted activation is not a fresh, complete, valid candidate."
        )
    return snapshot


def _recover_partial_later_snapshot(
    home: Path,
    profile: dict[str, Any],
    policy_digest: str,
    catalog_document: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    profile_id = profile["profileId"]
    v1_current, _ = _v1_high_water(home, profile, policy_digest)
    paths = GuardianPaths(home)
    snapshots: dict[int, dict[str, Any]] = {}
    for entry in _directory_entries(
        home,
        paths.rule_snapshots(profile_id),
        kind="Rule snapshot",
    ):
        try:
            assert_guardian_storage_path(home, entry)
            metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise RuleActivationError(
                f"Rule snapshot entry cannot be inspected: {error}"
            ) from error
        match = _SNAPSHOT_FILE.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
            raise RuleActivationError("Rule snapshot history contains an unexpected entry.")
        item = _load_document(home, profile, policy_digest, match.group(1))
        sequence = _sequence(item["approvalSequence"])
        if sequence in snapshots:
            raise RuleActivationError("Rule snapshot history reuses an approval sequence.")
        snapshots[sequence] = item

    records: dict[int, dict[str, Any]] = {}
    for entry in _directory_entries(
        home,
        paths.rule_approval_sequences(profile_id),
        kind="Rule approval-sequence",
    ):
        try:
            assert_guardian_storage_path(home, entry)
            metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise RuleActivationError(
                f"Rule sequence entry cannot be inspected: {error}"
            ) from error
        match = _SEQUENCE_FILE.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
            raise RuleActivationError("Rule sequence history contains an unexpected entry.")
        sequence = _sequence(int(match.group(1)))
        record = _read_link(
            home,
            entry,
            purpose=f"rule-approval-sequence:{profile_id}:{sequence}",
            missing_ok=False,
        )
        assert record is not None
        records[sequence] = record

    pointer = _read_link(
        home,
        paths.current_rule_snapshot(profile_id),
        purpose=f"current-rule-snapshot:{profile_id}",
        missing_ok=False,
    )
    assert pointer is not None
    partial_sequence = max(snapshots)
    current_sequence = _sequence(pointer["approvalSequence"])
    first_sequence = _sequence(v1_current["approvalSequence"]) + 1
    expected_snapshots = list(range(first_sequence, partial_sequence + 1))
    expected_current_records = list(range(first_sequence, current_sequence + 1))
    if (
        sorted(snapshots) != expected_snapshots
        or partial_sequence != current_sequence + 1
        or sorted(records)
        not in (expected_current_records, expected_current_records + [partial_sequence])
    ):
        raise RuleActivationError(
            "Interrupted v2 refresh does not contain one exact trailing snapshot."
        )
    current = snapshots.get(current_sequence)
    if current is None:
        raise RuleActivationError("Current v2 pointer has no retained snapshot.")
    pointer_unsigned = {
        key: value for key, value in pointer.items() if key != "authoritySeal"
    }
    if pointer_unsigned != _link_unsigned(current):
        raise RuleActivationError("Current v2 pointer conflicts with retained history.")

    previous_id = v1_current["snapshotId"]
    first_permission: str | None = None
    for sequence in expected_snapshots:
        item = snapshots[sequence]
        if item["previousSnapshotId"] != previous_id:
            raise RuleActivationError("Rule snapshot previousSnapshotId chain is invalid.")
        if first_permission is None:
            first_permission = item["firstActivationPermissionDigest"]
        elif item["firstActivationPermissionDigest"] != first_permission:
            raise RuleActivationError("Rule activation permission lineage changed.")
        record = records.get(sequence)
        if record is not None:
            record_unsigned = {
                key: value for key, value in record.items() if key != "authoritySeal"
            }
            if record_unsigned != _link_unsigned(item):
                raise RuleActivationError(
                    "Rule sequence record conflicts with its snapshot."
                )
        previous_id = item["snapshotId"]

    partial = snapshots[partial_sequence]
    catalog = _catalog_shape(catalog_document, profile_id)
    if partial["catalogEvidence"] != catalog:
        raise RuleActivationError(
            "Interrupted v2 refresh differs from the exact signed catalog retry."
        )
    return current, partial


def apply_rule_activation(home: Path, bundle: Any) -> dict[str, Any]:
    """Apply one exact permission-bound first activation, idempotently."""

    normalized_home = home.expanduser().absolute()
    profile_id, catalog, supplied_binding = _validate_bundle(bundle)
    try:
        with profile_transaction_lock(normalized_home, profile_id):
            if has_rule_namespace_evidence(normalized_home, profile_id):
                try:
                    existing = load_rule_snapshot(normalized_home, profile_id)
                except RuleActivationError:
                    snapshot = _recover_partial_first_activation(
                        normalized_home,
                        profile_id,
                        catalog,
                        supplied_binding,
                    )
                else:
                    if existing is None:
                        raise RuleActivationError(
                            "Rule activation evidence exists without a current v2 snapshot."
                        )
                    policy_digest = verify_policy_anchor(normalized_home)
                    profile = load_profile(normalized_home, profile_id)
                    _, base = _v1_high_water(
                        normalized_home, profile, policy_digest
                    )
                    normalized_catalog = _catalog_shape(catalog, profile_id)
                    expected_existing_binding = _permission_binding(
                        policy_digest=policy_digest,
                        profile=profile,
                        base=base,
                        catalog=normalized_catalog,
                        candidate=existing,
                    )
                    if (
                        supplied_binding != expected_existing_binding
                        or existing["catalogEvidence"] != normalized_catalog
                        or existing["firstActivationPermissionDigest"]
                        != sha256_digest(supplied_binding)
                    ):
                        raise RuleActivationError(
                            "Existing rule activation differs from the permitted candidate."
                        )
                    return {
                        "schemaVersion": 1,
                        "status": "allowed",
                        "profileId": profile_id,
                        "changed": False,
                        "snapshot": copy.deepcopy(existing),
                        "permissionRequired": False,
                        "localChangesPerformed": False,
                        "productionReady": False,
                    }
            else:
                assessment = _utc_now()
                profile, base, catalog, expected_binding = _prepare_first_activation(
                    normalized_home,
                    profile_id,
                    catalog,
                    require_fresh_complete=True,
                    assessed_at=assessment,
                )
                if supplied_binding != expected_binding:
                    raise RuleActivationError(
                        "Activation permission does not match the current exact candidate."
                    )
                unsigned = _build_unsigned_snapshot(
                    normalized_home,
                    profile,
                    catalog,
                    assessed_at=assessment,
                    policy_digest=expected_binding["policyDigest"],
                    previous_snapshot_id=base["snapshotId"],
                    first_permission_digest=sha256_digest(supplied_binding),
                )
                if (
                    unsigned["catalogDigest"]
                    != expected_binding["candidateCatalogDigest"]
                    or unsigned["rulesDigest"]
                    != expected_binding["candidateRulesDigest"]
                ):
                    raise RuleActivationError(
                        "Activation candidate changed after permission verification."
                    )
                snapshot = _seal_snapshot(normalized_home, unsigned)
            sequence_record = _sequence_record(normalized_home, snapshot)
            pointer = _current_pointer(normalized_home, snapshot)
            snapshot_path, sequence_path, pointer_path, changed = _preflight_first_storage(
                normalized_home,
                profile_id,
                snapshot,
                sequence_record,
                pointer,
            )
            if not snapshot_path.exists():
                exclusive_write_json(normalized_home, snapshot_path, snapshot)
            if not sequence_path.exists():
                exclusive_write_json(normalized_home, sequence_path, sequence_record)
            if not pointer_path.exists():
                contained_atomic_write_json(normalized_home, pointer_path, pointer)
            loaded = load_rule_snapshot(
                normalized_home,
                profile_id,
                snapshot["snapshotId"],
            )
            if loaded != snapshot:
                raise RuleActivationError("Rule activation failed post-write verification.")
    except RuleActivationError:
        raise
    except (AuthorityIntegrityError, OSError, PathIntegrityError, TimeoutError, ValueError) as error:
        raise RuleActivationError(f"Rule activation storage failed: {error}") from error
    return {
        "schemaVersion": 1,
        "status": "allowed",
        "profileId": profile_id,
        "changed": changed,
        "snapshot": copy.deepcopy(snapshot),
        "permissionRequired": False,
        "localChangesPerformed": changed,
        "productionReady": False,
    }


def ingest_rule_snapshot(
    home: Path, profile_document: Any, catalog_document: Any
) -> dict[str, Any]:
    """Append a later signed v2 catalog after first activation permission exists."""

    normalized_home = home.expanduser().absolute()
    policy_digest = verify_policy_anchor(normalized_home)
    profile = validate_profile(profile_document)
    installed = load_profile(normalized_home, profile["profileId"])
    if installed != profile:
        raise RuleActivationError("Rule snapshot profile differs from the installed profile.")
    paths = GuardianPaths(normalized_home)
    try:
        with profile_transaction_lock(normalized_home, profile["profileId"]):
            reloaded_profile = load_profile(normalized_home, profile["profileId"])
            if reloaded_profile != profile:
                raise RuleActivationError(
                    "Rule snapshot profile changed during ingestion."
                )
            try:
                current = load_rule_snapshot(normalized_home, profile["profileId"])
            except RuleActivationError:
                current, snapshot = _recover_partial_later_snapshot(
                    normalized_home,
                    profile,
                    policy_digest,
                    catalog_document,
                )
                sequence = snapshot["approvalSequence"]
                recovering = True
            else:
                if current is None:
                    raise RuleActivationError(
                        "First rule activation requires explicit permission."
                    )
                unsigned = _build_unsigned_snapshot(
                    normalized_home,
                    profile,
                    catalog_document,
                    assessed_at=_utc_now(),
                    policy_digest=policy_digest,
                    previous_snapshot_id=current["snapshotId"],
                    first_permission_digest=current[
                        "firstActivationPermissionDigest"
                    ],
                )
                sequence = unsigned["approvalSequence"]
                if sequence == current["approvalSequence"]:
                    if unsigned["approvalDigest"] != current["approvalDigest"]:
                        raise RuleActivationError(
                            "Current v2 approval sequence was reused for different content."
                        )
                    return copy.deepcopy(current)
                if sequence != current["approvalSequence"] + 1:
                    raise RuleActivationError(
                        "V2 approval sequence must advance exactly one."
                    )
                snapshot = _seal_snapshot(normalized_home, unsigned)
                recovering = False
            snapshot_path = paths.rule_snapshots(profile["profileId"]) / f"{snapshot['snapshotId']}.json"
            sequence_path = paths.rule_approval_sequences(profile["profileId"]) / f"{sequence}.json"
            expected_sequence = _sequence_record(normalized_home, snapshot)
            if recovering:
                if not snapshot_path.exists():
                    raise RuleActivationError(
                        "Interrupted v2 refresh lost its retained snapshot."
                    )
                if sequence_path.exists():
                    existing_sequence = _read_link(
                        normalized_home,
                        sequence_path,
                        purpose=(
                            f"rule-approval-sequence:{profile['profileId']}:{sequence}"
                        ),
                        missing_ok=False,
                    )
                    if existing_sequence != expected_sequence:
                        raise RuleActivationError(
                            "Interrupted v2 sequence differs from its signed snapshot."
                        )
                else:
                    exclusive_write_json(
                        normalized_home,
                        sequence_path,
                        expected_sequence,
                    )
            else:
                if snapshot_path.exists() or sequence_path.exists():
                    raise RuleActivationError(
                        "V2 approval sequence or snapshot already exists."
                    )
                exclusive_write_json(normalized_home, snapshot_path, snapshot)
                exclusive_write_json(
                    normalized_home,
                    sequence_path,
                    expected_sequence,
                )
            contained_atomic_write_json(
                normalized_home,
                paths.current_rule_snapshot(profile["profileId"]),
                _current_pointer(normalized_home, snapshot),
            )
            loaded = load_rule_snapshot(
                normalized_home,
                profile["profileId"],
                snapshot["snapshotId"],
            )
            if loaded != snapshot:
                raise RuleActivationError("Rule snapshot failed post-write verification.")
    except RuleActivationError:
        raise
    except (AuthorityIntegrityError, OSError, PathIntegrityError, TimeoutError, ValueError) as error:
        raise RuleActivationError(f"Rule snapshot ingestion failed: {error}") from error
    return copy.deepcopy(snapshot)


__all__ = [
    "ACTIVE_CAPABILITIES",
    "EVALUATOR_ID",
    "RuleActivationError",
    "apply_rule_activation",
    "has_rule_namespace_evidence",
    "ingest_rule_snapshot",
    "load_rule_snapshot",
    "preview_rule_activation",
]

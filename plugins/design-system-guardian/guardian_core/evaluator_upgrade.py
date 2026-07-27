"""Explicit evaluator-v2 authorization and privacy-safe rule inventory.

The rule-snapshot permission shipped in v0.3.5 remains authoritative only for
the v1 evaluator.  This module adds a separate, append-only local permission
sidecar for the v2 evaluator without rewriting snapshot or permission history.
"""

from __future__ import annotations

import copy
import re
import stat
from pathlib import Path
from typing import Any

from . import snapshot as catalog_snapshot
from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import read_canonical_json, sha256_digest
from .clock import utc_now as _utc_now
from .flutter_toolchain import (
    FlutterToolchainIntegrityError,
    FlutterToolchainUnsupportedError,
    select_profile_toolchain,
)
from .paths import (
    GuardianPaths,
    PathIntegrityError,
    assert_guardian_storage_path,
    is_link_or_reparse,
    validate_profile_id,
)
from .policy import verify_policy_anchor
from .profile import ProfileValidationError, load_profile
from .rule_activation import (
    ACTIVE_CAPABILITIES as LEGACY_ACTIVE_CAPABILITIES,
    EVALUATOR_ID as LEGACY_EVALUATOR_ID,
    RuleActivationError,
    has_rule_namespace_evidence,
    load_rule_snapshot,
)
from .storage import (
    contained_atomic_write_json,
    exclusive_write_json,
    profile_transaction_lock,
)


class EvaluatorUpgradeError(ValueError):
    """Raised when evaluator authorization evidence is invalid or divergent."""


class EvaluatorUpgradeSourceError(EvaluatorUpgradeError):
    """Raised when current source evidence cannot support this read/upgrade."""

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(f"Rule source evidence is {status}.")


class EvaluatorUpgradeCoverageError(EvaluatorUpgradeError):
    """Raised when the exact v2 evaluator cannot run for the selected profile."""


PREVIOUS_EVALUATOR_ID = LEGACY_EVALUATOR_ID
TARGET_EVALUATOR_ID = "guardian-flutter-usage-rules-v2"
AUTHORIZATION_NAMESPACE = "evaluator-authorizations-v1"
AUTHORIZATION_SCHEMA_VERSION = 1

EVALUATOR_CAPABILITY_MATRIX = {
    "predicates": [
        {
            "predicate": "forbidden_identity_in_scope",
            "relations": [],
            "scopes": ["compilation_unit", "widget_class"],
        },
        {
            "predicate": "max_instances_per_scope",
            "relations": [],
            "scopes": ["compilation_unit", "widget_class"],
        },
        {"predicate": "forbidden_nesting", "relations": [], "scopes": []},
        {
            "predicate": "required_companion",
            "relations": ["child", "descendant", "sibling"],
            "scopes": [],
        },
        {"predicate": "allowed_parents", "relations": [], "scopes": []},
        {
            "predicate": "variant_context",
            "relations": [],
            "scopes": ["compilation_unit", "widget_class"],
        },
    ],
    "relations": ["child", "descendant", "sibling"],
    "scopes": ["compilation_unit", "widget_class"],
}

EVALUATOR_CONTRACT = {
    "schemaVersion": 1,
    "evaluatorId": TARGET_EVALUATOR_ID,
    "identityResolution": "analyzer_resolved_exact_catalog_mapping",
    "constructionGraph": "resolved_constructor_syntactic_argument_containment",
    "widgetClassOwnership": "nearest_lexical_resolved_widget_or_state_widget_class",
    "positiveEvidence": "exact_positive_evidence_may_prove_violation",
    "absenceEvidence": "complete_scope_or_relationship_required",
    "suppressionHandling": "suppression_comments_remain_violations",
    "predicateContracts": [
        {
            "predicate": "forbidden_identity_in_scope",
            "violation": "exact_invocation_present",
            "pass": "complete_scope_without_exact_invocation",
        },
        {
            "predicate": "max_instances_per_scope",
            "violation": "exact_count_greater_than_max",
            "pass": "complete_scope_and_exact_count_at_most_max",
        },
        {
            "predicate": "forbidden_nesting",
            "violation": "exact_inner_proven_descendant_of_exact_outer",
            "pass": "all_relevant_outer_subtrees_complete_without_exact_inner",
        },
        {
            "predicate": "required_companion",
            "violation": "complete_declared_relation_without_exact_companion",
            "pass": "exact_companion_in_declared_relation",
        },
        {
            "predicate": "allowed_parents",
            "violation": "proven_root_or_proven_unapproved_immediate_parent",
            "pass": "proven_approved_immediate_parent",
        },
        {
            "predicate": "variant_context",
            "violation": "exact_mapped_variant_in_proven_disallowed_context",
            "pass": "exact_mapped_variant_in_at_least_one_complete_allowed_scope",
        },
    ],
    "capabilityMatrix": copy.deepcopy(EVALUATOR_CAPABILITY_MATRIX),
}
EVALUATOR_CONTRACT_DIGEST = sha256_digest(EVALUATOR_CONTRACT)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_AUTHORIZATION_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_MAX_SEQUENCE = (1 << 63) - 1
_BLOCKED_SOURCE_STATES = {"stale", "source_unavailable", "source_incomplete"}

_PERMISSION_BINDING_KEYS = {
    "schemaVersion",
    "authorizationSequence",
    "previousAuthorizationDigest",
    "profileId",
    "profileDigest",
    "policyDigest",
    "ruleSnapshotId",
    "ruleSnapshotApprovalSequence",
    "rulesDigest",
    "sourceCutDigest",
    "activationPermissionDigest",
    "catalogAuthorityKeyId",
    "previousEvaluatorId",
    "targetEvaluatorId",
    "evaluatorContractDigest",
    "capabilityMatrix",
    "namespaceTarget",
    "targetAuthorizationSchemaVersion",
}
_RECORD_KEYS = (_PERMISSION_BINDING_KEYS - {"targetEvaluatorId"}) | {
    "evaluatorId",
    "immutable",
    "authorizationDigest",
    "authoritySeal",
}
_POINTER_KEYS = {
    "schemaVersion",
    "profileId",
    "profileDigest",
    "policyDigest",
    "authorizationSequence",
    "authorizationDigest",
    "evaluatorId",
    "evaluatorContractDigest",
    "authoritySeal",
}


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise EvaluatorUpgradeError(
            f"{field} must be an exact lowercase SHA-256 digest."
        )
    return value


def _sequence(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_SEQUENCE
    ):
        raise EvaluatorUpgradeError(
            f"{field} must be an integer from 1 through {_MAX_SEQUENCE}."
        )
    return value


def _validate_permission_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PERMISSION_BINDING_KEYS:
        raise EvaluatorUpgradeError(
            "Evaluator upgrade permission has an invalid exact contract."
        )
    if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise EvaluatorUpgradeError("Evaluator permission schemaVersion must be 1.")
    if _sequence(value.get("authorizationSequence"), "authorizationSequence") != 1:
        raise EvaluatorUpgradeError("Evaluator authorization sequence must start at 1.")
    if value.get("previousAuthorizationDigest") is not None:
        raise EvaluatorUpgradeError(
            "The first evaluator authorization cannot claim a previous authorization."
        )
    profile_id = value.get("profileId")
    if not isinstance(profile_id, str):
        raise EvaluatorUpgradeError("Evaluator permission profileId is invalid.")
    try:
        validate_profile_id(profile_id)
    except ValueError as error:
        raise EvaluatorUpgradeError("Evaluator permission profileId is invalid.") from error
    for field in (
        "profileDigest",
        "policyDigest",
        "ruleSnapshotId",
        "rulesDigest",
        "sourceCutDigest",
        "activationPermissionDigest",
        "catalogAuthorityKeyId",
        "evaluatorContractDigest",
    ):
        _digest(value.get(field), field)
    _sequence(value.get("ruleSnapshotApprovalSequence"), "ruleSnapshotApprovalSequence")
    if value.get("previousEvaluatorId") != PREVIOUS_EVALUATOR_ID:
        raise EvaluatorUpgradeError("Evaluator permission previousEvaluatorId is invalid.")
    if value.get("targetEvaluatorId") != TARGET_EVALUATOR_ID:
        raise EvaluatorUpgradeError("Evaluator permission targetEvaluatorId is invalid.")
    if value.get("evaluatorContractDigest") != EVALUATOR_CONTRACT_DIGEST:
        raise EvaluatorUpgradeError("Evaluator contract digest is not the shipped v2 contract.")
    if value.get("capabilityMatrix") != EVALUATOR_CAPABILITY_MATRIX:
        raise EvaluatorUpgradeError("Evaluator capability matrix is not exact.")
    if value.get("namespaceTarget") != AUTHORIZATION_NAMESPACE:
        raise EvaluatorUpgradeError("Evaluator authorization namespace is invalid.")
    target_schema = value.get("targetAuthorizationSchemaVersion")
    if (
        type(target_schema) is not int
        or target_schema != AUTHORIZATION_SCHEMA_VERSION
    ):
        raise EvaluatorUpgradeError("Evaluator authorization target schema is invalid.")
    return copy.deepcopy(value)


def _record_binding(record: dict[str, Any]) -> dict[str, Any]:
    binding = {
        key: copy.deepcopy(record[key])
        for key in _PERMISSION_BINDING_KEYS
        if key != "targetEvaluatorId"
    }
    binding["targetEvaluatorId"] = record["evaluatorId"]
    return binding


def _build_record(home: Path, binding: dict[str, Any]) -> dict[str, Any]:
    exact = _validate_permission_binding(binding)
    record_fields = copy.deepcopy(exact)
    record_fields["evaluatorId"] = record_fields.pop("targetEvaluatorId")
    unsigned = {
        **record_fields,
        "immutable": True,
        "authorizationDigest": sha256_digest(exact),
    }
    return {
        **unsigned,
        "authoritySeal": authority_seal(home, "evaluator-authorization:v1", unsigned),
    }


def _pointer_unsigned(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "profileId": record["profileId"],
        "profileDigest": record["profileDigest"],
        "policyDigest": record["policyDigest"],
        "authorizationSequence": record["authorizationSequence"],
        "authorizationDigest": record["authorizationDigest"],
        "evaluatorId": record["evaluatorId"],
        "evaluatorContractDigest": record["evaluatorContractDigest"],
    }


def _build_pointer(home: Path, record: dict[str, Any]) -> dict[str, Any]:
    unsigned = _pointer_unsigned(record)
    purpose = f"current-evaluator-authorization:{record['profileId']}"
    return {**unsigned, "authoritySeal": authority_seal(home, purpose, unsigned)}


def _read_record(home: Path, path: Path, claimed_digest: str) -> dict[str, Any]:
    _digest(claimed_digest, "authorizationDigest")
    try:
        assert_guardian_storage_path(home, path)
        if is_link_or_reparse(path):
            raise EvaluatorUpgradeError(
                "Evaluator authorization records may not be redirected."
            )
        value = read_canonical_json(path)
        metadata = path.lstat()
        assert_guardian_storage_path(home, path)
    except EvaluatorUpgradeError:
        raise
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization record cannot be read safely: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvaluatorUpgradeError("Evaluator authorization record must be a regular file.")
    if not isinstance(value, dict) or set(value) != _RECORD_KEYS:
        raise EvaluatorUpgradeError(
            "Evaluator authorization record has unknown or missing fields."
        )
    binding = _validate_permission_binding(_record_binding(value))
    if value.get("immutable") is not True:
        raise EvaluatorUpgradeError("Evaluator authorization record is not immutable.")
    expected_digest = sha256_digest(binding)
    if value.get("authorizationDigest") != claimed_digest or expected_digest != claimed_digest:
        raise EvaluatorUpgradeError("Evaluator authorization content digest is invalid.")
    unsigned = {key: item for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(
            home,
            "evaluator-authorization:v1",
            unsigned,
            value["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization authority is invalid: {error}"
        ) from error
    return copy.deepcopy(value)


def _read_pointer(home: Path, profile_id: str) -> dict[str, Any]:
    path = GuardianPaths(home).current_evaluator_authorization(profile_id)
    try:
        assert_guardian_storage_path(home, path)
        if is_link_or_reparse(path):
            raise EvaluatorUpgradeError(
                "Evaluator authorization pointer may not be redirected."
            )
        value = read_canonical_json(path)
        metadata = path.lstat()
        assert_guardian_storage_path(home, path)
    except FileNotFoundError as error:
        raise EvaluatorUpgradeError(
            "Evaluator authorization pointer is missing from partial state."
        ) from error
    except EvaluatorUpgradeError:
        raise
    except (OSError, ValueError, UnicodeError, PathIntegrityError) as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization pointer cannot be read safely: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvaluatorUpgradeError("Evaluator authorization pointer must be a regular file.")
    if not isinstance(value, dict) or set(value) != _POINTER_KEYS:
        raise EvaluatorUpgradeError(
            "Evaluator authorization pointer has an invalid exact contract."
        )
    unsigned = {key: item for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(
            home,
            f"current-evaluator-authorization:{profile_id}",
            unsigned,
            value["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization pointer authority is invalid: {error}"
        ) from error
    return copy.deepcopy(value)


def _history_records(home: Path, profile_id: str) -> list[dict[str, Any]]:
    directory = GuardianPaths(home).evaluator_authorizations(profile_id)
    try:
        assert_guardian_storage_path(home, directory)
        if is_link_or_reparse(directory):
            raise EvaluatorUpgradeError(
                "Evaluator authorization history may not be redirected."
            )
        metadata = directory.lstat()
        entries = list(directory.iterdir())
        assert_guardian_storage_path(home, directory)
    except FileNotFoundError as error:
        raise EvaluatorUpgradeError(
            "Evaluator authorization history is missing from partial state."
        ) from error
    except EvaluatorUpgradeError:
        raise
    except (OSError, PathIntegrityError) as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization history cannot be inspected safely: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or not entries:
        raise EvaluatorUpgradeError(
            "Evaluator authorization history is empty or not a directory."
        )
    records: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda item: item.name):
        try:
            entry_metadata = entry.lstat()
            assert_guardian_storage_path(home, entry)
        except (OSError, PathIntegrityError) as error:
            raise EvaluatorUpgradeError(
                f"Evaluator authorization history entry cannot be inspected: {error}"
            ) from error
        match = _AUTHORIZATION_FILE.fullmatch(entry.name)
        if (
            match is None
            or not stat.S_ISREG(entry_metadata.st_mode)
            or is_link_or_reparse(entry)
        ):
            raise EvaluatorUpgradeError(
                "Evaluator authorization history contains an unexpected entry."
            )
        records.append(_read_record(home, entry, match.group(1)))
    return records


def has_evaluator_authorization_evidence(home: Path, profile_id: str) -> bool:
    """Return true for complete or partial sidecar state without repairing it."""

    normalized_home = home.expanduser().absolute()
    paths = GuardianPaths(normalized_home)
    try:
        for path in (
            paths.evaluator_authorizations(profile_id),
            paths.current_evaluator_authorization(profile_id),
        ):
            assert_guardian_storage_path(normalized_home, path)
            if path.exists() or is_link_or_reparse(path):
                return True
        return False
    except (OSError, PathIntegrityError) as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization namespace cannot be inspected: {error}"
        ) from error


def _load_rule_lineage(home: Path, profile_id: str) -> dict[str, Any]:
    try:
        current = load_rule_snapshot(home, profile_id)
    except RuleActivationError as error:
        raise EvaluatorUpgradeError(
            f"Current rule-snapshot lineage is invalid: {error}"
        ) from error
    if current is None:
        raise EvaluatorUpgradeCoverageError(
            "Evaluator v2 requires an explicit v0.3.5 rule activation first."
        )
    if (
        current.get("schemaVersion") != 2
        or current.get("activationEvaluatorId") != PREVIOUS_EVALUATOR_ID
        or current.get("activatedCapabilities") != LEGACY_ACTIVE_CAPABILITIES
    ):
        raise EvaluatorUpgradeError(
            "Current rule snapshot does not retain the exact v0.3.5 evaluator contract."
        )
    _digest(current.get("firstActivationPermissionDigest"), "firstActivationPermissionDigest")
    return current


def _verify_flutter_support(profile: dict[str, Any]) -> None:
    flutter = profile.get("adapters", {}).get("flutter")
    if not isinstance(flutter, dict) or flutter.get("enabled") is not True:
        raise EvaluatorUpgradeCoverageError(
            "The selected profile does not enable the supported Flutter adapter."
        )
    try:
        select_profile_toolchain(flutter.get("platformArtifacts"))
    except FlutterToolchainUnsupportedError as error:
        raise EvaluatorUpgradeCoverageError(
            "The selected profile has no supported Flutter adapter on this host."
        ) from error
    except FlutterToolchainIntegrityError as error:
        raise EvaluatorUpgradeError(f"Flutter adapter binding is invalid: {error}") from error


def _current_source_state(snapshot: dict[str, Any]) -> str:
    try:
        freshness = catalog_snapshot.classify_source_state(snapshot, now=_utc_now())
    except catalog_snapshot.SnapshotValidationError as error:
        raise EvaluatorUpgradeError(f"Rule source state is invalid: {error}") from error
    state = freshness["state"]
    rule_evidence = snapshot.get("ruleEvidence")
    if isinstance(rule_evidence, dict) and rule_evidence.get("sourceComplete") is not True:
        state = "source_incomplete"
    if state in _BLOCKED_SOURCE_STATES:
        raise EvaluatorUpgradeSourceError(state)
    return str(state)


def _candidate_binding(home: Path, profile_id: str) -> tuple[dict[str, Any], str]:
    policy_digest = verify_policy_anchor(home)
    try:
        profile = load_profile(home, profile_id)
    except ProfileValidationError as error:
        raise EvaluatorUpgradeError(f"Selected profile cannot be loaded: {error}") from error
    _verify_flutter_support(profile)
    current = _load_rule_lineage(home, profile_id)
    source_state = _current_source_state(current)
    rule_validation = current.get("ruleValidation")
    if not isinstance(rule_validation, dict) or rule_validation.get("status") == "invalid":
        raise EvaluatorUpgradeError(
            "Invalid rule evidence cannot authorize evaluator v2."
        )
    binding = {
        "schemaVersion": 1,
        "authorizationSequence": 1,
        "previousAuthorizationDigest": None,
        "profileId": profile_id,
        "profileDigest": sha256_digest(profile),
        "policyDigest": policy_digest,
        "ruleSnapshotId": current["snapshotId"],
        "ruleSnapshotApprovalSequence": current["approvalSequence"],
        "rulesDigest": current["rulesDigest"],
        "sourceCutDigest": sha256_digest(current["sourceCut"]),
        "activationPermissionDigest": current["firstActivationPermissionDigest"],
        "catalogAuthorityKeyId": current["approvalKeyId"],
        "previousEvaluatorId": PREVIOUS_EVALUATOR_ID,
        "targetEvaluatorId": TARGET_EVALUATOR_ID,
        "evaluatorContractDigest": EVALUATOR_CONTRACT_DIGEST,
        "capabilityMatrix": copy.deepcopy(EVALUATOR_CAPABILITY_MATRIX),
        "namespaceTarget": AUTHORIZATION_NAMESPACE,
        "targetAuthorizationSchemaVersion": AUTHORIZATION_SCHEMA_VERSION,
    }
    return _validate_permission_binding(binding), source_state


def _validate_authorized_lineage(
    home: Path,
    profile_id: str,
    record: dict[str, Any],
) -> None:
    policy_digest = verify_policy_anchor(home)
    try:
        profile = load_profile(home, profile_id)
    except ProfileValidationError as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization profile cannot be loaded: {error}"
        ) from error
    if record["profileId"] != profile_id or record["profileDigest"] != sha256_digest(profile):
        raise EvaluatorUpgradeError("Evaluator authorization crosses profile identity.")
    if record["policyDigest"] != policy_digest:
        raise EvaluatorUpgradeError("Evaluator authorization policy digest changed.")
    current = _load_rule_lineage(home, profile_id)
    try:
        authorized_snapshot = load_rule_snapshot(
            home,
            profile_id,
            record["ruleSnapshotId"],
        )
    except RuleActivationError as error:
        raise EvaluatorUpgradeError(
            f"Authorized rule snapshot cannot be loaded: {error}"
        ) from error
    if authorized_snapshot is None:
        raise EvaluatorUpgradeError(
            "Evaluator authorization references no retained rule snapshot."
        )
    expected = {
        "profileDigest": record["profileDigest"],
        "policyDigest": record["policyDigest"],
        "approvalSequence": record["ruleSnapshotApprovalSequence"],
        "rulesDigest": record["rulesDigest"],
        "sourceCutDigest": sha256_digest(authorized_snapshot["sourceCut"]),
        "firstActivationPermissionDigest": record["activationPermissionDigest"],
        "approvalKeyId": record["catalogAuthorityKeyId"],
    }
    actual = {
        "profileDigest": authorized_snapshot["profileDigest"],
        "policyDigest": authorized_snapshot["policyDigest"],
        "approvalSequence": authorized_snapshot["approvalSequence"],
        "rulesDigest": authorized_snapshot["rulesDigest"],
        "sourceCutDigest": sha256_digest(authorized_snapshot["sourceCut"]),
        "firstActivationPermissionDigest": authorized_snapshot[
            "firstActivationPermissionDigest"
        ],
        "approvalKeyId": authorized_snapshot["approvalKeyId"],
    }
    if actual != expected:
        raise EvaluatorUpgradeError(
            "Evaluator authorization no longer matches its retained rule snapshot."
        )
    if current["approvalSequence"] < authorized_snapshot["approvalSequence"]:
        raise EvaluatorUpgradeError("Current rule snapshot replays before evaluator authorization.")
    if (
        current["firstActivationPermissionDigest"]
        != record["activationPermissionDigest"]
        or current["approvalKeyId"] != record["catalogAuthorityKeyId"]
    ):
        raise EvaluatorUpgradeError(
            "Current rule snapshot left the authorized permission or catalog-authority lineage."
        )


def load_evaluator_authorization(
    home: Path,
    profile_id: str,
) -> dict[str, Any] | None:
    """Verify and return the effective v2 sidecar, never legacy permission."""

    normalized_home = home.expanduser().absolute()
    if not has_evaluator_authorization_evidence(normalized_home, profile_id):
        return None
    records = _history_records(normalized_home, profile_id)
    if len(records) != 1 or records[0]["authorizationSequence"] != 1:
        raise EvaluatorUpgradeError(
            "Evaluator authorization history is divergent or unsupported."
        )
    record = records[0]
    pointer = _read_pointer(normalized_home, profile_id)
    if {key: pointer[key] for key in pointer if key != "authoritySeal"} != _pointer_unsigned(
        record
    ):
        raise EvaluatorUpgradeError(
            "Current evaluator authorization pointer conflicts with append-only history."
        )
    _validate_authorized_lineage(normalized_home, profile_id, record)
    return copy.deepcopy(record)


def preview_evaluator_upgrade(home: Path, *, profile_id: str) -> dict[str, Any]:
    """Build an exact v2 permission request without changing local state."""

    normalized_home = home.expanduser().absolute()
    binding, _ = _candidate_binding(normalized_home, profile_id)
    if has_evaluator_authorization_evidence(normalized_home, profile_id):
        record = load_evaluator_authorization(normalized_home, profile_id)
        assert record is not None
        return {
            "schemaVersion": 1,
            "status": "allowed",
            "profileId": profile_id,
            "permissionRequired": False,
            "authorizationDigest": record["authorizationDigest"],
            "evaluatorId": TARGET_EVALUATOR_ID,
            "localChangesPerformed": False,
            "productionReady": False,
        }
    return {
        "schemaVersion": 1,
        "status": "permission_required",
        "profileId": profile_id,
        "permissionRequired": True,
        "permissionBinding": binding,
        "localChangesPerformed": False,
        "productionReady": False,
    }


def _validate_bundle(bundle: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(bundle, dict) or set(bundle) != {
        "schemaVersion",
        "profileId",
        "permission",
    }:
        raise EvaluatorUpgradeError(
            "Evaluator upgrade bundle has an invalid exact contract."
        )
    if type(bundle.get("schemaVersion")) is not int or bundle["schemaVersion"] != 1:
        raise EvaluatorUpgradeError("Evaluator upgrade bundle schemaVersion must be 1.")
    profile_id = bundle.get("profileId")
    if not isinstance(profile_id, str) or not profile_id:
        raise EvaluatorUpgradeError("Evaluator upgrade bundle profileId is invalid.")
    permission = bundle.get("permission")
    if not isinstance(permission, dict) or set(permission) != _PERMISSION_BINDING_KEYS | {
        "granted"
    }:
        raise EvaluatorUpgradeError(
            "Evaluator upgrade permission has an invalid exact contract."
        )
    if permission.get("granted") is not True:
        raise EvaluatorUpgradeError("Evaluator v2 permission was not granted.")
    binding = {
        key: copy.deepcopy(value)
        for key, value in permission.items()
        if key != "granted"
    }
    exact = _validate_permission_binding(binding)
    if exact["profileId"] != profile_id:
        raise EvaluatorUpgradeError(
            "Evaluator upgrade bundle and permission profiles differ."
        )
    return profile_id, exact


def _recover_exact_partial(
    home: Path,
    profile_id: str,
    supplied_binding: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    paths = GuardianPaths(home)
    history = paths.evaluator_authorizations(profile_id)
    pointer_path = paths.current_evaluator_authorization(profile_id)
    if pointer_path.exists() or is_link_or_reparse(pointer_path):
        raise EvaluatorUpgradeError(
            "Evaluator authorization pointer exists without valid complete history."
        )
    try:
        entries = [] if not history.exists() else list(history.iterdir())
    except OSError as error:
        raise EvaluatorUpgradeError(
            f"Partial evaluator authorization cannot be inspected: {error}"
        ) from error
    if entries:
        records = _history_records(home, profile_id)
        if len(records) != 1 or _record_binding(records[0]) != supplied_binding:
            raise EvaluatorUpgradeError(
                "Interrupted evaluator authorization differs from the granted permission."
            )
        record = records[0]
        _validate_authorized_lineage(home, profile_id, record)
    else:
        expected, _ = _candidate_binding(home, profile_id)
        if supplied_binding != expected:
            raise EvaluatorUpgradeError(
                "Evaluator permission does not match the current exact candidate."
            )
        record = _build_record(home, supplied_binding)
        exclusive_write_json(
            home,
            history / f"{record['authorizationDigest']}.json",
            record,
        )
    pointer = _build_pointer(home, record)
    contained_atomic_write_json(home, pointer_path, pointer)
    return record, True


def apply_evaluator_upgrade(home: Path, bundle: Any) -> dict[str, Any]:
    """Apply one exact v2 permission atomically and idempotently."""

    normalized_home = home.expanduser().absolute()
    profile_id, supplied_binding = _validate_bundle(bundle)
    changed = False
    try:
        with profile_transaction_lock(normalized_home, profile_id):
            if has_evaluator_authorization_evidence(normalized_home, profile_id):
                try:
                    record = load_evaluator_authorization(normalized_home, profile_id)
                except EvaluatorUpgradeError:
                    record, changed = _recover_exact_partial(
                        normalized_home,
                        profile_id,
                        supplied_binding,
                    )
                else:
                    assert record is not None
                    if _record_binding(record) != supplied_binding:
                        raise EvaluatorUpgradeError(
                            "Existing evaluator authorization differs from this permission."
                        )
            else:
                expected_binding, _ = _candidate_binding(normalized_home, profile_id)
                if supplied_binding != expected_binding:
                    raise EvaluatorUpgradeError(
                        "Evaluator permission does not match the current exact candidate."
                    )
                record = _build_record(normalized_home, supplied_binding)
                paths = GuardianPaths(normalized_home)
                exclusive_write_json(
                    normalized_home,
                    paths.evaluator_authorizations(profile_id)
                    / f"{record['authorizationDigest']}.json",
                    record,
                )
                contained_atomic_write_json(
                    normalized_home,
                    paths.current_evaluator_authorization(profile_id),
                    _build_pointer(normalized_home, record),
                )
                changed = True
            loaded = load_evaluator_authorization(normalized_home, profile_id)
            if loaded != record:
                raise EvaluatorUpgradeError(
                    "Evaluator authorization failed post-write verification."
                )
    except (EvaluatorUpgradeSourceError, EvaluatorUpgradeCoverageError):
        raise
    except EvaluatorUpgradeError:
        raise
    except (
        AuthorityIntegrityError,
        OSError,
        PathIntegrityError,
        TimeoutError,
        ValueError,
    ) as error:
        raise EvaluatorUpgradeError(
            f"Evaluator authorization storage failed: {error}"
        ) from error
    return {
        "schemaVersion": 1,
        "status": "allowed",
        "profileId": profile_id,
        "changed": changed,
        "authorization": copy.deepcopy(record),
        "permissionRequired": False,
        "localChangesPerformed": changed,
        "productionReady": False,
    }


def _v2_supports(predicate: dict[str, Any]) -> bool:
    predicate_type = predicate.get("type")
    capability = next(
        (
            item
            for item in EVALUATOR_CAPABILITY_MATRIX["predicates"]
            if item["predicate"] == predicate_type
        ),
        None,
    )
    if capability is None:
        return False
    scopes = capability["scopes"]
    if predicate_type in {"forbidden_identity_in_scope", "max_instances_per_scope"}:
        return predicate.get("scope") in scopes
    if predicate_type == "required_companion":
        return predicate.get("relation") in capability["relations"]
    if predicate_type == "variant_context":
        allowed_scopes = predicate.get("allowedScopes")
        return (
            isinstance(allowed_scopes, list)
            and bool(allowed_scopes)
            and all(scope in scopes for scope in allowed_scopes)
        )
    return predicate_type in {"forbidden_nesting", "allowed_parents"}


def _legacy_supports(predicate: dict[str, Any]) -> bool:
    return {
        "predicate": predicate.get("type"),
        "scope": predicate.get("scope"),
    } in LEGACY_ACTIVE_CAPABILITIES


def _inventory_entry(
    rule: dict[str, Any],
    *,
    evaluator_state: str,
) -> dict[str, Any]:
    rule_class = rule["class"]
    predicate = rule.get("predicate")
    predicate_type = predicate.get("type") if isinstance(predicate, dict) else None
    if rule_class == "informative":
        capability_status = "informative"
        reason_code = "informative_non_gating"
    elif rule_class == "judgment":
        capability_status = "not_assessed"
        reason_code = "judgment_rule_not_assessed"
    elif evaluator_state == "authorized_v2" and isinstance(predicate, dict) and _v2_supports(
        predicate
    ):
        capability_status = "active"
        reason_code = "evaluator_capability_active"
    elif evaluator_state == "legacy_v1" and isinstance(predicate, dict) and _legacy_supports(
        predicate
    ):
        capability_status = "active"
        reason_code = "evaluator_capability_active"
    elif evaluator_state == "legacy_v1":
        capability_status = "not_assessed"
        reason_code = "evaluator_upgrade_required"
    else:
        capability_status = "not_assessed"
        reason_code = "unsupported_evaluator_capability"
    return {
        "ruleId": rule["ruleId"],
        "ruleClass": rule_class,
        "predicate": predicate_type,
        "capabilityStatus": capability_status,
        "reasonCode": reason_code,
    }


def list_rules(home: Path, *, profile_id: str) -> dict[str, Any]:
    """Return a canonical privacy-safe inventory without writing any state."""

    normalized_home = home.expanduser().absolute()
    verify_policy_anchor(normalized_home)
    try:
        load_profile(normalized_home, profile_id)
    except ProfileValidationError as error:
        raise EvaluatorUpgradeError(f"Selected profile cannot be loaded: {error}") from error

    if has_rule_namespace_evidence(normalized_home, profile_id):
        current = _load_rule_lineage(normalized_home, profile_id)
        rules = current["rules"]
        rules_digest = current["rulesDigest"]
        authorization = load_evaluator_authorization(normalized_home, profile_id)
        evaluator_state = "authorized_v2" if authorization is not None else "legacy_v1"
    else:
        try:
            current = catalog_snapshot.load_snapshot(normalized_home, profile_id)
        except catalog_snapshot.SnapshotValidationError as error:
            raise EvaluatorUpgradeError(
                f"Current pre-activation snapshot is invalid: {error}"
            ) from error
        rules = []
        rules_digest = sha256_digest(rules)
        authorization = None
        evaluator_state = "pre_activation"
    source_state = _current_source_state(current)

    entries = [
        _inventory_entry(rule, evaluator_state=evaluator_state)
        for rule in sorted(rules, key=lambda item: item["ruleId"])
    ]
    summary = {
        "active": sum(item["capabilityStatus"] == "active" for item in entries),
        "informative": sum(
            item["capabilityStatus"] == "informative" for item in entries
        ),
        "notAssessed": sum(
            item["capabilityStatus"] == "not_assessed" for item in entries
        ),
    }
    incomplete_v2 = evaluator_state == "authorized_v2" and summary["notAssessed"] > 0
    return {
        "schemaVersion": 1,
        "status": "not_assessed" if incomplete_v2 else "allowed",
        "profileId": profile_id,
        "ruleSnapshotId": current["snapshotId"],
        "rulesDigest": rules_digest,
        "sourceState": source_state,
        "evaluatorState": evaluator_state,
        "evaluatorId": (
            TARGET_EVALUATOR_ID
            if evaluator_state == "authorized_v2"
            else PREVIOUS_EVALUATOR_ID
            if evaluator_state == "legacy_v1"
            else None
        ),
        "evaluatorContractDigest": (
            authorization["evaluatorContractDigest"] if authorization is not None else None
        ),
        "authorizationDigest": (
            authorization["authorizationDigest"] if authorization is not None else None
        ),
        "rules": entries,
        "summary": summary,
        "localChangesPerformed": False,
        "productionReady": False,
    }


__all__ = [
    "AUTHORIZATION_NAMESPACE",
    "EVALUATOR_CAPABILITY_MATRIX",
    "EVALUATOR_CONTRACT",
    "EVALUATOR_CONTRACT_DIGEST",
    "EvaluatorUpgradeCoverageError",
    "EvaluatorUpgradeError",
    "EvaluatorUpgradeSourceError",
    "PREVIOUS_EVALUATOR_ID",
    "TARGET_EVALUATOR_ID",
    "apply_evaluator_upgrade",
    "has_evaluator_authorization_evidence",
    "list_rules",
    "load_evaluator_authorization",
    "preview_evaluator_upgrade",
]

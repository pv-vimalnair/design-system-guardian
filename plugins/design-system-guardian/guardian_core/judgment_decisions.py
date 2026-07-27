"""Permission-bound exact-run judgment decisions and append-only revocation history."""
from __future__ import annotations

import copy
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .adapter_dispatch import build_pinned_adapter_config
from .audit import project_audit_result_v1
from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .audit_attestation import AnalysisAttestationIntegrityError, verify_analysis_attestation
from .canonical import read_canonical_json, sha256_digest
from .clock import utc_now as _utc_now
from .evaluator_upgrade import EvaluatorUpgradeError, load_evaluator_authorization
from .judgment_assessment import (
    JudgmentAssessmentIntegrityError, build_judgment_assessment,
    derive_effective_judgment, validate_judgment_assessment,
)
from .paths import (
    GuardianPaths, PathIntegrityError, assert_guardian_storage_path,
    is_link_or_reparse,
)
from .preflight import PreflightError, load_run_pin
from .rule_activation import RuleActivationError, load_rule_snapshot
from .run_artifacts import (
    RunArtifactIntegrityError, read_run_artifact, read_run_artifact_if_present,
    seal_run_artifact, write_run_artifact,
)
from .storage import contained_atomic_write_json, exclusive_write_json, profile_transaction_lock

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FINDING_ID = re.compile(r"^finding-[0-9a-f]{24}$")
_HISTORY_FILE = re.compile(r"^([0-9]{8})-([0-9a-f]{64})\.json$")
_ASSESSMENT_BINDINGS = {
    "runPinDigest", "profileDigest", "policyDigest", "snapshotDigest",
    "sourceCutDigest", "ruleSnapshotDigest", "activeRuleSetDigest",
    "evaluatorContractDigest", "analysisAttestationDigest", "auditResultDigest",
    "targetDigest", "evidenceDigest",
}
_APPROVAL_PERMISSION_KEYS = {
    "schemaVersion", "action", "profileId", "runId", "sequence",
    "previousRecordDigest", "assessmentDigest", "candidateDigest",
    "selectedFindings", "reason", "runManifestDigest",
    "evaluatorAuthorizationDigest", *_ASSESSMENT_BINDINGS,
}
_REVOCATION_PERMISSION_KEYS = {
    "schemaVersion", "action", "profileId", "runId", "sequence",
    "previousRecordDigest", "assessmentDigest", "decisionDigest",
    "runManifestDigest", "evaluatorAuthorizationDigest", *_ASSESSMENT_BINDINGS,
}
_RECORD_KEYS = {
    "schemaVersion", "recordType", "profileId", "runId", "sequence",
    "previousRecordDigest", "assessmentDigest", "decisionDigest",
    "revokedDecisionDigest", "selectedFindings", "reason", "decidedAt",
    "bindings", "permissionBinding", "permissionDigest", "authoritySeal",
}
_HEAD_KEYS = {
    "schemaVersion", "profileId", "runId", "sequence", "recordDigest",
    "assessmentDigest", "activeDecisionDigest", "authoritySeal",
}


class JudgmentDecisionIntegrityError(ValueError):
    """Raised when a decision, inherited binding, or history is ambiguous."""

    def __init__(
        self,
        *args: object,
        local_changes_performed: bool = False,
    ) -> None:
        if type(local_changes_performed) is not bool:
            raise TypeError("local_changes_performed must be boolean.")
        super().__init__(*args)
        self.local_changes_performed = local_changes_performed


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise JudgmentDecisionIntegrityError(f"{field} must be an object.")
    return copy.deepcopy(dict(value))


def _exact(value: Mapping[str, Any], keys: set[str], field: str) -> None:
    if set(value) != keys:
        raise JudgmentDecisionIntegrityError(f"{field} has unknown or missing fields.")


def _digest(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise JudgmentDecisionIntegrityError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _sequence(value: Any, field: str = "sequence") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 99999999:
        raise JudgmentDecisionIntegrityError(f"{field} is invalid.")
    return value


def _reason(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 1024 or "\x00" in value:
        raise JudgmentDecisionIntegrityError("reason must be optional bounded text.")
    return value


def _selected(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 8192:
        raise JudgmentDecisionIntegrityError("selectedFindings must be a bounded list.")
    normalized = []
    for raw in value:
        item = _mapping(raw, "selected finding")
        _exact(item, {"findingId", "rawStatus"}, "selected finding")
        if (
            not isinstance(item.get("findingId"), str)
            or _FINDING_ID.fullmatch(item["findingId"]) is None
            or item.get("rawStatus") != "conflict"
        ):
            raise JudgmentDecisionIntegrityError("Only exact raw conflict findings can be selected.")
        normalized.append(item)
    ids = [item["findingId"] for item in normalized]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise JudgmentDecisionIntegrityError("Selected findings must be unique and canonical.")
    return normalized


def _validate_candidate(value: Any) -> dict[str, Any]:
    candidate = _mapping(value, "candidate")
    _exact(candidate, {"candidateResults", "selection", "reason"}, "candidate")
    if not isinstance(candidate.get("candidateResults"), list) or len(candidate["candidateResults"]) > 8192:
        raise JudgmentDecisionIntegrityError("candidateResults must be a bounded list.")
    selection = _mapping(candidate.get("selection"), "candidate.selection")
    _exact(selection, {"mode", "findingIds"}, "candidate.selection")
    mode, ids = selection.get("mode"), selection.get("findingIds")
    if mode not in {"all_conflicts", "finding_ids"} or not isinstance(ids, list) or len(ids) > 8192:
        raise JudgmentDecisionIntegrityError("candidate selection is invalid.")
    if any(not isinstance(item, str) or _FINDING_ID.fullmatch(item) is None for item in ids):
        raise JudgmentDecisionIntegrityError("candidate finding ID is invalid.")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise JudgmentDecisionIntegrityError("candidate finding IDs must be unique and canonical.")
    if mode == "all_conflicts" and ids:
        raise JudgmentDecisionIntegrityError("all_conflicts cannot include explicit IDs.")
    candidate["reason"] = _reason(candidate.get("reason"))
    return candidate


def _unsigned(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(item) for key, item in value.items() if key != "authoritySeal"}


def _reopen_context(home: Path, *, profile_id: str, run_id: str) -> dict[str, Any]:
    """Reopen all retained authority sources for one exact finalized run."""
    try:
        pinned = load_run_pin(home, profile_id=profile_id, run_id=run_id)
        pin, profile = pinned["pin"], pinned["profile"]
        snapshot = load_rule_snapshot(home, profile_id, pin["snapshotId"])
        if snapshot is None:
            raise JudgmentDecisionIntegrityError("Pinned active rule snapshot is not retained.")
        authorization = load_evaluator_authorization(home, profile_id)
        if authorization is None:
            raise JudgmentDecisionIntegrityError("Evaluator authorization is not available.")
        envelopes = {
            kind: read_run_artifact(
                home, profile_id=profile_id, run_id=run_id, artifact_type=kind
            )
            for kind in ("analysis-attestation", "audit-result", "run-manifest")
        }
    except JudgmentDecisionIntegrityError:
        raise
    except (
        EvaluatorUpgradeError, PreflightError, RuleActivationError,
        RunArtifactIntegrityError, OSError, ValueError,
    ) as error:
        raise JudgmentDecisionIntegrityError(f"Exact run evidence cannot be reopened: {error}") from error
    analysis = envelopes["analysis-attestation"]["payload"]
    audit = envelopes["audit-result"]["payload"]
    manifest = envelopes["run-manifest"]["payload"]
    for name, document in (
        ("analysis attestation", analysis), ("audit result", audit), ("run manifest", manifest)
    ):
        for field, expected in (
            ("runId", run_id), ("profileId", profile_id), ("policyDigest", pin["policyDigest"])
        ):
            if document.get(field) != expected:
                raise JudgmentDecisionIntegrityError(f"{name} {field} differs from the exact run.")
    if manifest.get("snapshotId") != pin["snapshotId"] or manifest.get("sourceCut") != pin["sourceCut"]:
        raise JudgmentDecisionIntegrityError("Run manifest differs from the pinned source.")
    inputs, outputs = manifest.get("inputs"), manifest.get("outputs")
    if not isinstance(inputs, list) or not isinstance(outputs, list):
        raise JudgmentDecisionIntegrityError("Run manifest bindings are incomplete.")
    input_map = {item.get("artifactType"): item.get("digest") for item in inputs if isinstance(item, Mapping)}
    output_map = {item.get("artifactType"): item.get("payloadDigest") for item in outputs if isinstance(item, Mapping)}
    if len(input_map) != len(inputs) or len(output_map) != len(outputs):
        raise JudgmentDecisionIntegrityError("Run manifest artifact bindings are duplicated.")
    if (
        input_map.get("run-pin") != sha256_digest(pin)
        or input_map.get("analysis-attestation") != envelopes["analysis-attestation"]["payloadDigest"]
        or input_map.get("audit-result") != sha256_digest(audit)
        or output_map.get("audit-result") != envelopes["audit-result"]["payloadDigest"]
    ):
        raise JudgmentDecisionIntegrityError("Run manifest artifact digests no longer match.")
    if authorization.get("profileId") != profile_id:
        raise JudgmentDecisionIntegrityError("Evaluator authorization crosses profile identity.")
    adapter_config = None
    attested_audit = audit
    attested_config_digest = analysis.get("configDigest")
    if audit.get("coverage", {}).get("adapter") == "flutter":
        try:
            _, adapter_config = build_pinned_adapter_config(
                home,
                profile_id=profile_id,
                run_id=run_id,
                adapter="flutter",
            )
            attested_audit = project_audit_result_v1(audit)
        except (OSError, ValueError) as error:
            raise JudgmentDecisionIntegrityError(
                f"Pinned Flutter adapter config cannot be regenerated: {error}"
            ) from error
        if not isinstance(adapter_config, Mapping):
            raise JudgmentDecisionIntegrityError(
                "Pinned Flutter adapter config is invalid."
            )
        attested_config_digest = adapter_config.get("configDigest")
        if (
            attested_config_digest != analysis.get("configDigest")
            or attested_config_digest != audit.get("coverage", {}).get("configDigest")
        ):
            raise JudgmentDecisionIntegrityError(
                "Pinned Flutter adapter config differs from finalized evidence."
            )
    try:
        verify_analysis_attestation(
            analysis,
            run_pin=pin,
            config_digest=attested_config_digest,
            audit_result=attested_audit,
            verified_snapshot=snapshot,
            adapter_config=adapter_config,
        )
    except (AnalysisAttestationIntegrityError, KeyError, TypeError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(
            f"Analysis attestation cannot be reverified: {error}"
        ) from error
    return {
        "runPin": pin, "profile": profile, "ruleSnapshot": snapshot,
        "analysisAttestation": analysis, "auditResult": audit,
        "runManifest": manifest, "evaluatorAuthorization": authorization,
    }


def _build_assessment(context: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return dict(build_judgment_assessment(
            run_pin=context["runPin"], rule_snapshot=context["ruleSnapshot"],
            analysis_attestation=context["analysisAttestation"],
            audit_result=context["auditResult"],
            candidate_results=copy.deepcopy(candidate["candidateResults"]),
        ))
    except (JudgmentAssessmentIntegrityError, KeyError, TypeError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(f"Judgment assessment is invalid: {error}") from error


def _choose_findings(assessment: Mapping[str, Any], candidate: Mapping[str, Any]) -> list[dict[str, str]]:
    conflicts = {
        finding["findingId"]: {"findingId": finding["findingId"], "rawStatus": "conflict"}
        for instance in assessment["instances"] if instance["rawStatus"] == "conflict"
        for finding in instance["findings"]
    }
    ids = (
        sorted(conflicts)
        if candidate["selection"]["mode"] == "all_conflicts"
        else candidate["selection"]["findingIds"]
    )
    if any(item not in conflicts for item in ids):
        raise JudgmentDecisionIntegrityError("Selection contains an unknown or non-conflict finding.")
    return [conflicts[item] for item in ids]


def _permission_binding(context, assessment, candidate, selected, *, sequence, previous):
    return {
        "schemaVersion": 1, "action": "approve",
        "profileId": assessment["profileId"], "runId": assessment["runId"],
        "sequence": sequence, "previousRecordDigest": previous,
        "assessmentDigest": sha256_digest(assessment),
        "candidateDigest": sha256_digest(candidate),
        "selectedFindings": copy.deepcopy(selected), "reason": candidate["reason"],
        **copy.deepcopy(assessment["bindings"]),
        "runManifestDigest": sha256_digest(context["runManifest"]),
        "evaluatorAuthorizationDigest": sha256_digest(context["evaluatorAuthorization"]),
    }


def _validate_approval_permission(value: Any) -> dict[str, Any]:
    permission = _mapping(value, "approval permission")
    _exact(permission, _APPROVAL_PERMISSION_KEYS, "approval permission")
    if permission.get("schemaVersion") != 1 or permission.get("action") != "approve":
        raise JudgmentDecisionIntegrityError("Approval permission purpose is invalid.")
    if not isinstance(permission.get("profileId"), str) or not isinstance(permission.get("runId"), str):
        raise JudgmentDecisionIntegrityError("Approval permission identity is invalid.")
    _sequence(permission.get("sequence"))
    _digest(permission.get("previousRecordDigest"), "previousRecordDigest", nullable=True)
    for field in _ASSESSMENT_BINDINGS | {
        "assessmentDigest", "candidateDigest", "runManifestDigest", "evaluatorAuthorizationDigest",
    }:
        _digest(permission.get(field), field)
    permission["selectedFindings"] = _selected(permission.get("selectedFindings"))
    permission["reason"] = _reason(permission.get("reason"))
    return permission


def _validate_revocation_permission(value: Any) -> dict[str, Any]:
    permission = _mapping(value, "revocation permission")
    _exact(permission, _REVOCATION_PERMISSION_KEYS, "revocation permission")
    if permission.get("schemaVersion") != 1 or permission.get("action") != "revoke":
        raise JudgmentDecisionIntegrityError("Revocation permission purpose is invalid.")
    if not isinstance(permission.get("profileId"), str) or not isinstance(permission.get("runId"), str):
        raise JudgmentDecisionIntegrityError("Revocation permission identity is invalid.")
    _sequence(permission.get("sequence"))
    for field in _ASSESSMENT_BINDINGS | {
        "previousRecordDigest", "assessmentDigest", "decisionDigest",
        "runManifestDigest", "evaluatorAuthorizationDigest",
    }:
        _digest(permission.get(field), field)
    return permission

def _history_paths(home: Path, profile_id: str, run_id: str) -> tuple[Path, Path]:
    try:
        paths = GuardianPaths(home)
        return (
            assert_guardian_storage_path(home, paths.judgment_history(profile_id, run_id)),
            assert_guardian_storage_path(home, paths.current_judgment_history(profile_id, run_id)),
        )
    except (PathIntegrityError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(f"Judgment history path is unsafe: {error}") from error


def _validate_record(home: Path, value: Any) -> dict[str, Any]:
    record = _mapping(value, "judgment history record")
    _exact(record, _RECORD_KEYS, "judgment history record")
    if record.get("schemaVersion") != 1 or record.get("recordType") not in {"approval", "revocation"}:
        raise JudgmentDecisionIntegrityError("Judgment history record version or type is invalid.")
    if not isinstance(record.get("profileId"), str) or not isinstance(record.get("runId"), str):
        raise JudgmentDecisionIntegrityError("Judgment record identity is invalid.")
    _sequence(record.get("sequence"))
    _digest(record.get("previousRecordDigest"), "record.previousRecordDigest", nullable=True)
    _digest(record.get("assessmentDigest"), "record.assessmentDigest")
    _digest(record.get("decisionDigest"), "record.decisionDigest", nullable=True)
    _digest(record.get("revokedDecisionDigest"), "record.revokedDecisionDigest", nullable=True)
    selected, reason = _selected(record.get("selectedFindings")), _reason(record.get("reason"))
    if not isinstance(record.get("decidedAt"), str) or not record["decidedAt"].endswith("Z"):
        raise JudgmentDecisionIntegrityError("Judgment record time is invalid.")
    bindings = _mapping(record.get("bindings"), "record.bindings")
    _exact(
        bindings,
        _ASSESSMENT_BINDINGS | {"runManifestDigest", "evaluatorAuthorizationDigest"},
        "record.bindings",
    )
    for field, digest in bindings.items():
        _digest(digest, f"record.bindings.{field}")
    if record["recordType"] == "approval":
        permission = _validate_approval_permission(record.get("permissionBinding"))
        if record.get("decisionDigest") != sha256_digest(permission) or record.get("revokedDecisionDigest") is not None:
            raise JudgmentDecisionIntegrityError("Approval record decision fields are invalid.")
        if selected != permission["selectedFindings"] or reason != permission["reason"]:
            raise JudgmentDecisionIntegrityError("Approval record differs from its permission.")
    else:
        permission = _validate_revocation_permission(record.get("permissionBinding"))
        if record.get("decisionDigest") is not None or record.get("revokedDecisionDigest") is None:
            raise JudgmentDecisionIntegrityError("Revocation record decision fields are invalid.")
        if selected or reason is not None:
            raise JudgmentDecisionIntegrityError("Revocation cannot select findings or a reason.")
    if record.get("permissionDigest") != sha256_digest(permission):
        raise JudgmentDecisionIntegrityError("Judgment record permission digest is invalid.")
    if (
        record["profileId"] != permission["profileId"]
        or record["runId"] != permission["runId"]
        or record["sequence"] != permission["sequence"]
        or record["previousRecordDigest"] != permission["previousRecordDigest"]
        or record["assessmentDigest"] != permission["assessmentDigest"]
    ):
        raise JudgmentDecisionIntegrityError("Judgment record permission identity differs.")
    if bindings != {key: permission[key] for key in bindings}:
        raise JudgmentDecisionIntegrityError("Judgment record inherited bindings differ.")
    try:
        verify_authority_seal(
            home,
            f"judgment-history:{record['profileId']}:{record['runId']}:{record['sequence']}",
            _unsigned(record), record.get("authoritySeal"),
        )
    except AuthorityIntegrityError as error:
        raise JudgmentDecisionIntegrityError(f"Judgment record authority seal is invalid: {error}") from error
    return record


def _validate_head(home: Path, value: Any) -> dict[str, Any]:
    head = _mapping(value, "judgment history head")
    _exact(head, _HEAD_KEYS, "judgment history head")
    if head.get("schemaVersion") != 1:
        raise JudgmentDecisionIntegrityError("Judgment history head version is invalid.")
    if not isinstance(head.get("profileId"), str) or not isinstance(head.get("runId"), str):
        raise JudgmentDecisionIntegrityError("Judgment history head identity is invalid.")
    _sequence(head.get("sequence"))
    _digest(head.get("recordDigest"), "head.recordDigest")
    _digest(head.get("assessmentDigest"), "head.assessmentDigest")
    _digest(head.get("activeDecisionDigest"), "head.activeDecisionDigest", nullable=True)
    try:
        verify_authority_seal(
            home, f"current-judgment-history:{head['profileId']}:{head['runId']}",
            _unsigned(head), head.get("authoritySeal"),
        )
    except AuthorityIntegrityError as error:
        raise JudgmentDecisionIntegrityError(f"Judgment head authority seal is invalid: {error}") from error
    return head


def _read_history(home: Path, profile_id: str, run_id: str, *, allow_partial=False):
    history_path, head_path = _history_paths(home, profile_id, run_id)
    try:
        if is_link_or_reparse(history_path) or is_link_or_reparse(head_path):
            raise JudgmentDecisionIntegrityError("Judgment history may not use redirected paths.")
        entries = [] if not history_path.exists() else list(history_path.iterdir())
    except OSError as error:
        raise JudgmentDecisionIntegrityError(f"Judgment history cannot be inspected: {error}") from error
    records = []
    for entry in entries:
        try:
            assert_guardian_storage_path(home, entry)
            metadata = entry.lstat()
        except (OSError, PathIntegrityError) as error:
            raise JudgmentDecisionIntegrityError(f"Judgment history entry is unsafe: {error}") from error
        match = _HISTORY_FILE.fullmatch(entry.name)
        if match is None or not stat.S_ISREG(metadata.st_mode) or is_link_or_reparse(entry):
            raise JudgmentDecisionIntegrityError("Judgment history contains an unexpected entry.")
        try:
            record = _validate_record(home, read_canonical_json(entry))
        except JudgmentDecisionIntegrityError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise JudgmentDecisionIntegrityError(f"Judgment history entry is invalid: {error}") from error
        if int(match.group(1)) != record["sequence"] or match.group(2) != sha256_digest(record):
            raise JudgmentDecisionIntegrityError("Judgment history filename does not bind its record.")
        records.append(record)
    records.sort(key=lambda item: item["sequence"])
    if [item["sequence"] for item in records] != list(range(1, len(records) + 1)):
        raise JudgmentDecisionIntegrityError("Judgment history contains a gap or fork.")
    previous = active = None
    active_after = []
    for record in records:
        digest = sha256_digest(record)
        if record["previousRecordDigest"] != previous:
            raise JudgmentDecisionIntegrityError("Judgment previous-record chain is invalid.")
        if record["recordType"] == "approval":
            active = record["decisionDigest"]
        else:
            if active is None or record["revokedDecisionDigest"] != active:
                raise JudgmentDecisionIntegrityError("Revocation does not bind the active decision.")
            active = None
        previous = digest
        active_after.append(active)
    if not head_path.exists():
        if records:
            if not allow_partial:
                raise JudgmentDecisionIntegrityError("Judgment history head is missing.")
            first = records[0]
            if (
                len(records) != 1
                or first["recordType"] != "approval"
                or first["profileId"] != profile_id
                or first["runId"] != run_id
                or first["previousRecordDigest"] is not None
            ):
                raise JudgmentDecisionIntegrityError(
                    "Judgment history lacks an exact recoverable first-record head."
                )
        return records, None
    try:
        head = _validate_head(home, read_canonical_json(head_path))
    except JudgmentDecisionIntegrityError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(f"Judgment history head is invalid: {error}") from error
    if not records:
        raise JudgmentDecisionIntegrityError("Judgment history head exists without records.")
    last = records[-1]
    if (
        head["profileId"] == profile_id
        and head["runId"] == run_id
        and head["sequence"] == last["sequence"]
        and head["recordDigest"] == sha256_digest(last)
        and head["assessmentDigest"] == last["assessmentDigest"]
        and head["activeDecisionDigest"] == active
    ):
        return records, head
    if not allow_partial or len(records) < 2:
        raise JudgmentDecisionIntegrityError(
            "Judgment head conflicts with append-only history."
        )
    prefix = records[-2]
    prefix_active = active_after[-2]
    same_inherited_binding = all(
        record["profileId"] == profile_id
        and record["runId"] == run_id
        and record["assessmentDigest"] == head["assessmentDigest"]
        and record["bindings"] == prefix["bindings"]
        for record in records
    )
    valid_transition = (
        last["recordType"] == "approval"
        and prefix_active is None
        and active == last["decisionDigest"]
    ) or (
        last["recordType"] == "revocation"
        and prefix_active is not None
        and last["revokedDecisionDigest"] == prefix_active
        and active is None
    )
    if (
        head["profileId"] == profile_id
        and head["runId"] == run_id
        and head["sequence"] == prefix["sequence"] == last["sequence"] - 1
        and head["recordDigest"] == sha256_digest(prefix)
        and head["assessmentDigest"] == prefix["assessmentDigest"]
        and head["activeDecisionDigest"] == prefix_active
        and last["previousRecordDigest"] == head["recordDigest"]
        and same_inherited_binding
        and valid_transition
    ):
        return records, None
    raise JudgmentDecisionIntegrityError(
        "Judgment head conflicts with append-only history."
    )


def _head(home: Path, record: Mapping[str, Any], active: str | None) -> dict[str, Any]:
    unsigned = {
        "schemaVersion": 1, "profileId": record["profileId"], "runId": record["runId"],
        "sequence": record["sequence"], "recordDigest": sha256_digest(record),
        "assessmentDigest": record["assessmentDigest"], "activeDecisionDigest": active,
    }
    return {
        **unsigned,
        "authoritySeal": authority_seal(
            home, f"current-judgment-history:{record['profileId']}:{record['runId']}", unsigned
        ),
    }


def _record(home, permission, *, record_type, revoked_decision_digest=None):
    binding_keys = _ASSESSMENT_BINDINGS | {
        "runManifestDigest", "evaluatorAuthorizationDigest"
    }
    unsigned = {
        "schemaVersion": 1, "recordType": record_type,
        "profileId": permission["profileId"], "runId": permission["runId"],
        "sequence": permission["sequence"],
        "previousRecordDigest": permission["previousRecordDigest"],
        "assessmentDigest": permission["assessmentDigest"],
        "decisionDigest": sha256_digest(permission) if record_type == "approval" else None,
        "revokedDecisionDigest": revoked_decision_digest,
        "selectedFindings": copy.deepcopy(permission.get("selectedFindings", [])),
        "reason": permission.get("reason"),
        "decidedAt": _utc_now().isoformat().replace("+00:00", "Z"),
        "bindings": {key: copy.deepcopy(permission[key]) for key in binding_keys},
        "permissionBinding": copy.deepcopy(dict(permission)),
        "permissionDigest": sha256_digest(permission),
    }
    return {
        **unsigned,
        "authoritySeal": authority_seal(
            home,
            f"judgment-history:{permission['profileId']}:{permission['runId']}:{permission['sequence']}",
            unsigned,
        ),
    }


def _write_record(home: Path, record: Mapping[str, Any]) -> None:
    history_path, _ = _history_paths(home, record["profileId"], record["runId"])
    digest = sha256_digest(record)
    path = history_path / f"{record['sequence']:08d}-{digest}.json"
    try:
        exclusive_write_json(home, path, dict(record))
    except FileExistsError:
        try:
            existing = read_canonical_json(path)
        except (OSError, UnicodeError, ValueError) as error:
            raise JudgmentDecisionIntegrityError(f"Interrupted record is unreadable: {error}") from error
        if existing != record:
            raise JudgmentDecisionIntegrityError("Divergent retry conflicts with append-only history.")


def _explanation(assessment):
    findings = [
        {
            "findingId": finding["findingId"], "ruleId": finding["ruleId"],
            "targetId": finding["targetId"], "whatFailed": finding["explanation"],
            "whyItMatters": finding["impact"],
            "recommendedCorrection": finding["correction"],
            "evidenceReferences": copy.deepcopy(finding["evidenceReferences"]),
        }
        for instance in assessment["instances"]
        for finding in instance["findings"]
    ]
    return {
        "summary": (
            "The exact run has judgment conflicts. Review what failed and why before deciding."
            if findings else
            "The exact run has a complete positive report that still requires approval."
        ),
        "findings": findings,
        "options": ["Fix and evaluate again", "Approve this exact version anyway"],
    }

def preview_judgment_decision(
    home: Path, *, profile_id: str, run_id: str, candidate: dict[str, object]
) -> dict[str, object]:
    """Reopen one exact run and explain a zero-write candidate."""
    home = home.expanduser().absolute()
    candidate = _validate_candidate(candidate)
    context = _reopen_context(home, profile_id=profile_id, run_id=run_id)
    assessment = _build_assessment(context, candidate)
    if not assessment["complete"]:
        raise JudgmentDecisionIntegrityError("not_assessed judgment evidence cannot be approved.")
    if not assessment["nonJudgmentBlockersClear"]:
        raise JudgmentDecisionIntegrityError("A hard non-judgment lane blocks an exception.")
    selected = _choose_findings(assessment, candidate)
    records, head = _read_history(home, profile_id, run_id)
    if head is not None and head["activeDecisionDigest"] is not None:
        current = records[-1]
        binding = _permission_binding(
            context, assessment, candidate, selected,
            sequence=current["sequence"], previous=current["previousRecordDigest"],
        )
        if current["recordType"] == "approval" and current["permissionBinding"] == binding:
            return {
                "schemaVersion": 1, "status": "active", "profileId": profile_id,
                "runId": run_id, "permissionRequired": False,
                "permissionBinding": binding, "explanation": _explanation(assessment),
                "localChangesPerformed": False, "productionReady": False,
            }
        raise JudgmentDecisionIntegrityError("A different active decision already exists.")
    binding = _permission_binding(
        context, assessment, candidate, selected,
        sequence=len(records) + 1,
        previous=None if not records else sha256_digest(records[-1]),
    )
    return {
        "schemaVersion": 1, "status": "permission_required",
        "profileId": profile_id, "runId": run_id, "permissionRequired": True,
        "permissionBinding": binding, "explanation": _explanation(assessment),
        "localChangesPerformed": False, "productionReady": False,
    }


def _validate_apply_bundle(bundle: Any):
    value = _mapping(bundle, "decision bundle")
    _exact(
        value,
        {"schemaVersion", "profileId", "runId", "candidate", "permission"},
        "decision bundle",
    )
    if value.get("schemaVersion") != 1:
        raise JudgmentDecisionIntegrityError("Decision bundle schemaVersion must be 1.")
    profile_id, run_id = value.get("profileId"), value.get("runId")
    if not isinstance(profile_id, str) or not isinstance(run_id, str):
        raise JudgmentDecisionIntegrityError("Decision bundle identity is invalid.")
    candidate = _validate_candidate(value.get("candidate"))
    raw = _mapping(value.get("permission"), "decision permission")
    if set(raw) != _APPROVAL_PERMISSION_KEYS | {"granted"}:
        raise JudgmentDecisionIntegrityError("Decision permission has an invalid exact contract.")
    granted = raw.pop("granted")
    if not isinstance(granted, bool):
        raise JudgmentDecisionIntegrityError("Decision granted must be boolean.")
    permission = _validate_approval_permission(raw)
    if permission["profileId"] != profile_id or permission["runId"] != run_id:
        raise JudgmentDecisionIntegrityError("Decision crosses profile or run identity.")
    return profile_id, run_id, candidate, permission, granted


def apply_judgment_decision(home: Path, bundle: object) -> dict[str, object]:
    """Apply one exact grant; explicit denial writes no state."""
    home = home.expanduser().absolute()
    profile_id, run_id, candidate, supplied, granted = _validate_apply_bundle(bundle)
    if not granted:
        return {
            "schemaVersion": 1, "status": "denied", "profileId": profile_id,
            "runId": run_id, "changed": False, "localChangesPerformed": False,
            "productionReady": False,
        }
    local_changes_performed = False
    try:
        with profile_transaction_lock(home, profile_id):
            context = _reopen_context(home, profile_id=profile_id, run_id=run_id)
            assessment = _build_assessment(context, candidate)
            if not assessment["complete"] or not assessment["nonJudgmentBlockersClear"]:
                raise JudgmentDecisionIntegrityError("Current exact run is not eligible.")
            selected = _choose_findings(assessment, candidate)
            records, head = _read_history(home, profile_id, run_id, allow_partial=True)
            if head is not None and head["activeDecisionDigest"] is not None:
                current = records[-1]
                expected_active = _permission_binding(
                    context, assessment, candidate, selected,
                    sequence=current["sequence"],
                    previous=current["previousRecordDigest"],
                )
                if (
                    current["recordType"] == "approval"
                    and current["permissionBinding"] == supplied == expected_active
                    and current["assessmentDigest"] == sha256_digest(assessment)
                ):
                    return {
                        "schemaVersion": 1, "status": "active", "profileId": profile_id,
                        "runId": run_id, "changed": False, "decision": current,
                        "localChangesPerformed": False, "productionReady": False,
                    }
                raise JudgmentDecisionIntegrityError("Existing decision differs from exact retry.")
            if records and head is None:
                partial = records[-1]
                expected = _permission_binding(
                    context, assessment, candidate, selected,
                    sequence=partial["sequence"],
                    previous=partial["previousRecordDigest"],
                )
                if (
                    partial["recordType"] != "approval"
                    or partial["permissionBinding"] != supplied
                    or supplied != expected
                ):
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted decision differs from the reevaluated exact retry."
                    )
            else:
                expected = _permission_binding(
                    context, assessment, candidate, selected,
                    sequence=len(records) + 1,
                    previous=None if not records else sha256_digest(records[-1]),
                )
            if supplied != expected:
                raise JudgmentDecisionIntegrityError(
                    "Permission does not match the reevaluated exact candidate."
                )
            stored_assessment = {
                "schemaVersion": 1, "profileId": profile_id, "runId": run_id,
                "policyDigest": assessment["bindings"]["policyDigest"],
                "assessmentDigest": sha256_digest(assessment),
                "assessment": copy.deepcopy(assessment),
            }
            envelope = seal_run_artifact(
                home, artifact_type="judgment-assessment",
                profile_id=profile_id, run_id=run_id, payload=stored_assessment,
            )
            write_run_artifact(home, envelope)
            local_changes_performed = True
            if records and head is None:
                partial = records[-1]
                if partial["recordType"] != "approval" or partial["permissionBinding"] != supplied:
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted decision differs from the exact granted retry."
                    )
                record = partial
            else:
                record = _record(home, supplied, record_type="approval")
                _write_record(home, record)
                local_changes_performed = True
            _, head_path = _history_paths(home, profile_id, run_id)
            contained_atomic_write_json(
                home, head_path, _head(home, record, record["decisionDigest"])
            )
            loaded, loaded_head = _read_history(home, profile_id, run_id)
            if loaded[-1] != record or loaded_head is None:
                raise JudgmentDecisionIntegrityError("Decision failed post-write verification.")
    except JudgmentDecisionIntegrityError as error:
        if local_changes_performed and not error.local_changes_performed:
            raise JudgmentDecisionIntegrityError(
                *error.args,
                local_changes_performed=True,
            ) from error
        raise
    except (AuthorityIntegrityError, OSError, PathIntegrityError, TimeoutError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(
            f"Decision storage failed: {error}",
            local_changes_performed=local_changes_performed,
        ) from error
    return {
        "schemaVersion": 1, "status": "active", "profileId": profile_id,
        "runId": run_id, "changed": True, "decision": copy.deepcopy(record),
        "localChangesPerformed": True, "productionReady": False,
    }


def _status_from_state(home, profile_id, run_id, context, assessment, records, head):
    active = head["activeDecisionDigest"] is not None
    approval = records[-1] if active else next(
        (item for item in reversed(records) if item["recordType"] == "approval"), None
    )
    selected = (
        [item["findingId"] for item in approval["selectedFindings"]]
        if active and approval is not None else []
    )
    try:
        projection = derive_effective_judgment(
            assessment,
            {"active": active, "assessmentDigest": sha256_digest(assessment),
             "selectedFindingIds": selected},
            enforcement_authority_lane=context["runManifest"]["enforcementAuthorityLane"],
        )
    except (JudgmentAssessmentIntegrityError, KeyError, TypeError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(f"Effective judgment is invalid: {error}") from error
    result = {
        "schemaVersion": 1, "status": "active" if active else "revoked",
        "profileId": profile_id, "runId": run_id,
        "assessment": copy.deepcopy(assessment), "historyHead": copy.deepcopy(head),
        "effectiveProjection": projection, "revocationPermissionBinding": None,
        "localChangesPerformed": False,
        "productionReady": bool(projection["productionReady"]),
    }
    if active:
        result["revocationPermissionBinding"] = _revocation_binding(
            context, assessment, records[-1], sequence=len(records) + 1,
            previous=sha256_digest(records[-1]),
        )
    return result


def _validate_stored_assessment(envelope, context):
    if envelope is None:
        raise JudgmentDecisionIntegrityError("Sealed judgment assessment is missing.")
    try:
        stored = envelope["payload"]
        if set(stored) != {
            "schemaVersion", "profileId", "runId", "policyDigest",
            "assessmentDigest", "assessment",
        }:
            raise JudgmentDecisionIntegrityError(
                "Stored assessment envelope payload is invalid."
            )
        assessment = validate_judgment_assessment(
            stored["assessment"], run_pin=context["runPin"],
            rule_snapshot=context["ruleSnapshot"],
            analysis_attestation=context["analysisAttestation"],
            audit_result=context["auditResult"],
        )
    except (JudgmentAssessmentIntegrityError, KeyError, TypeError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(f"Stored assessment is invalid: {error}") from error
    if stored["assessmentDigest"] != sha256_digest(assessment):
        raise JudgmentDecisionIntegrityError("Stored assessment digest is invalid.")
    return assessment


def _revocation_binding(context, assessment, approval, *, sequence, previous):
    return {
        "schemaVersion": 1, "action": "revoke",
        "profileId": assessment["profileId"], "runId": assessment["runId"],
        "sequence": sequence, "previousRecordDigest": previous,
        "assessmentDigest": sha256_digest(assessment),
        "decisionDigest": approval["decisionDigest"],
        **copy.deepcopy(assessment["bindings"]),
        "runManifestDigest": sha256_digest(context["runManifest"]),
        "evaluatorAuthorizationDigest": sha256_digest(context["evaluatorAuthorization"]),
    }


def read_judgment_status(
    home: Path, *, profile_id: str, run_id: str
) -> dict[str, object]:
    """Read and reevaluate the current exact-run state without writing."""
    home = home.expanduser().absolute()
    records, head = _read_history(home, profile_id, run_id)
    assessment_envelope = read_run_artifact_if_present(
        home, profile_id=profile_id, run_id=run_id,
        artifact_type="judgment-assessment",
    )
    if not records and head is None and assessment_envelope is None:
        return {
            "schemaVersion": 1, "status": "not_assessed",
            "profileId": profile_id, "runId": run_id,
            "assessment": None, "historyHead": None, "effectiveProjection": None,
            "revocationPermissionBinding": None, "localChangesPerformed": False,
            "productionReady": False,
        }
    if not records or head is None or assessment_envelope is None:
        raise JudgmentDecisionIntegrityError("Judgment state is partial or divergent.")
    context = _reopen_context(home, profile_id=profile_id, run_id=run_id)
    assessment = _validate_stored_assessment(assessment_envelope, context)
    if any(item["assessmentDigest"] != sha256_digest(assessment) for item in records):
        raise JudgmentDecisionIntegrityError("History crosses assessment identity.")
    return _status_from_state(
        home, profile_id, run_id, context, assessment, records, head
    )

def _validate_revoke_bundle(bundle: Any):
    value = _mapping(bundle, "revocation bundle")
    _exact(value, {"schemaVersion", "profileId", "runId", "permission"}, "revocation bundle")
    if value.get("schemaVersion") != 1:
        raise JudgmentDecisionIntegrityError("Revocation schemaVersion must be 1.")
    profile_id, run_id = value.get("profileId"), value.get("runId")
    if not isinstance(profile_id, str) or not isinstance(run_id, str):
        raise JudgmentDecisionIntegrityError("Revocation identity is invalid.")
    raw = _mapping(value.get("permission"), "revocation permission")
    if set(raw) != _REVOCATION_PERMISSION_KEYS | {"granted"}:
        raise JudgmentDecisionIntegrityError("Revocation permission contract is invalid.")
    granted = raw.pop("granted")
    if not isinstance(granted, bool):
        raise JudgmentDecisionIntegrityError("Revocation granted must be boolean.")
    permission = _validate_revocation_permission(raw)
    if permission["profileId"] != profile_id or permission["runId"] != run_id:
        raise JudgmentDecisionIntegrityError("Revocation crosses profile or run identity.")
    return profile_id, run_id, permission, granted


def revoke_judgment_decision(home: Path, bundle: object) -> dict[str, object]:
    """Append one exact revocation without editing prior bytes."""
    home = home.expanduser().absolute()
    profile_id, run_id, supplied, granted = _validate_revoke_bundle(bundle)
    if not granted:
        return {
            "schemaVersion": 1, "status": "active", "profileId": profile_id,
            "runId": run_id, "changed": False, "localChangesPerformed": False,
            "productionReady": False,
        }
    local_changes_performed = False
    try:
        with profile_transaction_lock(home, profile_id):
            records, head = _read_history(home, profile_id, run_id, allow_partial=True)
            if head is not None and head["activeDecisionDigest"] is None:
                current = records[-1]
                if current["recordType"] == "revocation" and current["permissionBinding"] == supplied:
                    read_judgment_status(home, profile_id=profile_id, run_id=run_id)
                    return {
                        "schemaVersion": 1, "status": "revoked", "profileId": profile_id,
                        "runId": run_id, "changed": False, "revocation": current,
                        "localChangesPerformed": False, "productionReady": False,
                    }
                raise JudgmentDecisionIntegrityError("Existing revocation differs from exact retry.")
            if records and head is None:
                partial = records[-1]
                if len(records) < 2 or partial["recordType"] != "revocation":
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted revocation has no retained active decision."
                    )
                context = _reopen_context(
                    home, profile_id=profile_id, run_id=run_id
                )
                assessment_envelope = read_run_artifact_if_present(
                    home, profile_id=profile_id, run_id=run_id,
                    artifact_type="judgment-assessment",
                )
                assessment = _validate_stored_assessment(
                    assessment_envelope, context
                )
                if any(
                    item["assessmentDigest"] != sha256_digest(assessment)
                    for item in records
                ):
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted revocation crosses assessment identity."
                    )
                approval = records[-2]
                expected = _revocation_binding(
                    context, assessment, approval,
                    sequence=partial["sequence"],
                    previous=partial["previousRecordDigest"],
                )
                if partial["permissionBinding"] != supplied or supplied != expected:
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted revocation differs from reevaluated exact status."
                    )
            else:
                status = read_judgment_status(home, profile_id=profile_id, run_id=run_id)
                expected = status.get("revocationPermissionBinding")
            if supplied != expected:
                raise JudgmentDecisionIntegrityError(
                    "Revocation does not match the current zero-write status."
                )
            if records and head is None:
                partial = records[-1]
                if partial["recordType"] != "revocation" or partial["permissionBinding"] != supplied:
                    raise JudgmentDecisionIntegrityError(
                        "Interrupted revocation differs from exact retry."
                    )
                record = partial
            else:
                record = _record(
                    home, supplied, record_type="revocation",
                    revoked_decision_digest=supplied["decisionDigest"],
                )
                _write_record(home, record)
                local_changes_performed = True
            _, head_path = _history_paths(home, profile_id, run_id)
            contained_atomic_write_json(home, head_path, _head(home, record, None))
            loaded, loaded_head = _read_history(home, profile_id, run_id)
            if loaded[-1] != record or loaded_head is None:
                raise JudgmentDecisionIntegrityError("Revocation failed post-write verification.")
    except JudgmentDecisionIntegrityError as error:
        if local_changes_performed and not error.local_changes_performed:
            raise JudgmentDecisionIntegrityError(
                *error.args,
                local_changes_performed=True,
            ) from error
        raise
    except (AuthorityIntegrityError, OSError, PathIntegrityError, TimeoutError, ValueError) as error:
        raise JudgmentDecisionIntegrityError(
            f"Revocation storage failed: {error}",
            local_changes_performed=local_changes_performed,
        ) from error
    return {
        "schemaVersion": 1, "status": "revoked", "profileId": profile_id,
        "runId": run_id, "changed": True, "revocation": copy.deepcopy(record),
        "localChangesPerformed": True, "productionReady": False,
    }


__all__ = [
    "JudgmentDecisionIntegrityError", "preview_judgment_decision",
    "apply_judgment_decision", "read_judgment_status",
    "revoke_judgment_decision",
]
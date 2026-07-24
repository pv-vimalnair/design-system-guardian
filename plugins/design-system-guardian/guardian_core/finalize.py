"""Fail-closed run finalization over a verified immutable task pin."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditIntegrityError, derive_audit_exit_code
from .audit_attestation import AnalysisAttestationIntegrityError, verify_analysis_attestation
from .canonical import canonical_json_bytes, sha256_digest
from .clock import utc_now as _utc_now
from .contracts import ExitCode
from .enforcement_authority import (
    EnforcementAuthorityIntegrityError,
    canonicalize_enforcement_authority_lane,
)
from .flutter_config import _generate_flutter_adapter_config_at_home
from .post_run import build_post_run_assessment
from .preflight import PreflightError, load_run_pin
from .project_binding import ProjectBindingError, project_evidence_matches_binding
from .release import RUNTIME_VERSION
from .resolver import _resolve_verified_snapshot_identity
from .run_artifacts import RunArtifactIntegrityError, read_run_artifact, read_run_artifact_if_present, render_audit_report, seal_run_artifact, write_readable_report, write_run_artifact
from .sentinels import SentinelIntegrityError, validate_sentinel
from .snapshot import SnapshotValidationError, classify_source_state

_BUILD_KEYS = {"schemaVersion", "runId", "profileId", "snapshotId", "policyDigest", "uxDecision", "selections", "sentinels", "productionReady"}
_UX_KEYS = {"hierarchy", "states", "accessibility", "componentIntent"}

class FinalizationError(ValueError):
    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY

@dataclass(frozen=True)
class FinalizationResult:
    manifest: dict[str, Any]
    exit_code: ExitCode
    production_ready: bool
    post_run_assessment: dict[str, Any]
    artifact_paths: dict[str, Path]

def _timestamp(value: Any, field: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value:
        raise FinalizationError(f"{field} must be an ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise FinalizationError(f"{field} is invalid.") from error
    if parsed.tzinfo is None:
        raise FinalizationError(f"{field} must include an offset.")
    utc = parsed.astimezone(timezone.utc)
    return utc, utc.isoformat().replace("+00:00", "Z")

def _combine(*codes: ExitCode) -> ExitCode:
    rank = {ExitCode.PASS: 0, ExitCode.VIOLATION_OR_SENTINEL: 1, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE: 2, ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE: 3, ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY: 4}
    return max(codes, key=rank.__getitem__)

def _plan(
    value: Any,
    pin: dict[str, Any],
    snapshot: dict[str, Any],
    audit_resolutions: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, ExitCode]:
    if value is None:
        return None, ExitCode.PASS
    if not isinstance(value, dict) or set(value) != _BUILD_KEYS or value.get("schemaVersion") != 1:
        raise FinalizationError("Build plan has unknown, missing, or invalid fields.")
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        if value.get(field) != pin[field]:
            raise FinalizationError(f"Build plan {field} differs from the run pin.")
    ux = value.get("uxDecision")
    if (
        not isinstance(ux, dict)
        or set(ux) != _UX_KEYS
        or any(not isinstance(ux[key], list) or not ux[key] for key in _UX_KEYS)
        or any(not isinstance(item, str) or not item.strip() for key in _UX_KEYS for item in ux[key])
    ):
        raise FinalizationError("Build plan UX decision must cover every required area with non-empty text.")
    if not isinstance(value.get("selections"), list) or not isinstance(value.get("sentinels"), list) or not isinstance(value.get("productionReady"), bool):
        raise FinalizationError("Build plan arrays or productionReady are invalid.")

    normalized = copy.deepcopy(value)
    normalized_selections: list[dict[str, Any]] = []
    for selection in normalized["selections"]:
        if not isinstance(selection, dict) or not isinstance(selection.get("request"), dict):
            raise FinalizationError("Every build selection must be one complete Guardian resolution.")
        expected = _resolve_verified_snapshot_identity(
            profile_id=pin["profileId"], snapshot=snapshot,
            request=selection["request"], policy_digest=pin["policyDigest"],
        )
        if expected.get("status") != "allowed" or selection != expected:
            raise FinalizationError("Build selection is not the exact authoritative allowed resolution.")
        normalized_selections.append(expected)
    selection_bytes = [canonical_json_bytes(item) for item in normalized_selections]
    if len(selection_bytes) != len(set(selection_bytes)):
        raise FinalizationError("Build selections must not contain duplicate evidence.")
    audited_allowed = [item for item in audit_resolutions if item.get("status") == "allowed"]
    if sorted(selection_bytes) != sorted(canonical_json_bytes(item) for item in audited_allowed):
        raise FinalizationError("Build selections differ from the exact allowed audit resolutions.")
    normalized["selections"] = sorted(normalized_selections, key=canonical_json_bytes)

    normalized_sentinels = []
    for sentinel in normalized["sentinels"]:
        try:
            normalized_sentinels.append(validate_sentinel(sentinel, policy_digest=pin["policyDigest"]))
        except SentinelIntegrityError as error:
            raise FinalizationError(f"Build plan contains a non-canonical sentinel: {error}") from error
    audited_sentinels = [item["sentinel"] for item in audit_resolutions if item.get("sentinel") is not None]
    if sorted(canonical_json_bytes(item) for item in normalized_sentinels) != sorted(canonical_json_bytes(item) for item in audited_sentinels):
        raise FinalizationError("Build sentinels differ from the exact audited missing resolutions.")
    normalized["sentinels"] = sorted(normalized_sentinels, key=canonical_json_bytes)
    if normalized["sentinels"] or normalized["productionReady"] is not True:
        normalized["productionReady"] = False
        return normalized, ExitCode.VIOLATION_OR_SENTINEL
    return normalized, ExitCode.PASS

def _audit(
    value: Any,
    pin: dict[str, Any],
    snapshot: dict[str, Any],
) -> tuple[dict[str, Any], ExitCode]:
    if not isinstance(value, dict):
        raise FinalizationError("Finalization requires an audit object.")
    result = copy.deepcopy(value)
    resolutions = result.get("resolutions")
    if not isinstance(resolutions, list):
        raise FinalizationError("Audit resolutions must be an array.")
    for resolution in resolutions:
        if not isinstance(resolution, dict) or not isinstance(resolution.get("request"), dict):
            raise FinalizationError("Every audit resolution must carry one exact request.")
        expected = _resolve_verified_snapshot_identity(
            profile_id=pin["profileId"], snapshot=snapshot,
            request=resolution["request"], policy_digest=pin["policyDigest"],
        )
        if resolution != expected:
            raise FinalizationError(
                "Audit resolution is not the exact authoritative pinned-snapshot result."
            )
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        if result.get(field) != pin[field]:
            raise FinalizationError(f"Audit result {field} differs from the run pin.")
    try:
        result["projectEvidence"] = project_evidence_matches_binding(
            result.get("projectEvidence"), pin["projectBinding"]
        )
    except ProjectBindingError as error:
        raise FinalizationError(f"Audit project evidence is invalid: {error}") from error
    try:
        result["enforcementAuthorityLane"] = canonicalize_enforcement_authority_lane(
            result.get("enforcementAuthorityLane")
        )
    except EnforcementAuthorityIntegrityError as error:
        raise FinalizationError(f"Enforcement authority lane is invalid: {error}") from error
    lane = result.get("designSystemLane")
    if not isinstance(lane, dict) or lane.get("sourceCutDigest") != sha256_digest(pin["sourceCut"]):
        raise FinalizationError("Audit result is not bound to the pinned source cut.")
    try:
        code = derive_audit_exit_code(result)
    except AuditIntegrityError as error:
        raise FinalizationError(str(error)) from error
    result["productionReady"] = code == ExitCode.PASS
    if code == ExitCode.VIOLATION_OR_SENTINEL and lane.get("status") == "allowed":
        lane["status"] = "conflict"
    return result, code

def _rel(home: Path, path: Path) -> str:
    return path.relative_to(home).as_posix()

def _finalize_run_at(home: Path, *, profile_id: str, run_id: str, audit_result: dict[str, Any], build_plan: dict[str, Any] | None, started_at: str, completed_at: str) -> FinalizationResult:
    home = home.expanduser().absolute()
    try:
        context = load_run_pin(home, profile_id=profile_id, run_id=run_id)
        pin = context["pin"]
        snapshot = context["snapshot"]
    except (PreflightError, OSError, ValueError) as error:
        raise FinalizationError(f"Verified run pin cannot be loaded: {error}") from error
    started, started_text = _timestamp(started_at, "startedAt")
    completed, completed_text = _timestamp(completed_at, "completedAt")
    if completed < started:
        raise FinalizationError("completedAt cannot precede startedAt.")
    try:
        completion_freshness = classify_source_state(snapshot, now=completed)
    except SnapshotValidationError as error:
        raise FinalizationError(f"Pinned snapshot freshness evidence is invalid: {error}") from error
    audit, audit_code = _audit(audit_result, pin, snapshot)
    try:
        expected_adapter_config = _generate_flutter_adapter_config_at_home(
            home,
            profile_id=profile_id,
            run_id=run_id,
        )
    except (OSError, ValueError) as error:
        raise FinalizationError(f"Pinned adapter config cannot be regenerated: {error}") from error
    if audit["coverage"]["configDigest"] != expected_adapter_config["configDigest"]:
        raise FinalizationError("Audit coverage is not bound to the exact pinned adapter config.")
    try:
        analysis_envelope = read_run_artifact(
            home,
            profile_id=profile_id,
            run_id=run_id,
            artifact_type="analysis-attestation",
        )
        verify_analysis_attestation(
            analysis_envelope["payload"],
            run_pin=pin,
            config_digest=expected_adapter_config["configDigest"],
            audit_result=audit_result,
        )
    except (RunArtifactIntegrityError, AnalysisAttestationIntegrityError, KeyError) as error:
        raise FinalizationError(
            f"Trusted analysis attestation cannot be verified: {error}"
        ) from error
    completion_state = completion_freshness["state"]
    if completion_state in {"stale", "source_unavailable", "source_incomplete"}:
        audit["designSystemLane"]["status"] = completion_state
        audit["productionReady"] = False
        try:
            audit_code = derive_audit_exit_code(audit)
        except AuditIntegrityError as error:
            raise FinalizationError(str(error)) from error
    plan, plan_code = _plan(build_plan, pin, snapshot, audit["resolutions"])
    code = _combine(audit_code, plan_code)
    ready = code == ExitCode.PASS
    audit["productionReady"] = ready
    if plan is not None:
        plan["productionReady"] = ready
    try:
        artifacts: dict[str, Path] = {}
        outputs: list[dict[str, Any]] = []
        inputs = [
            {"artifactType": "run-pin", "digest": sha256_digest(pin)},
            {"artifactType": "analysis-attestation", "digest": analysis_envelope["payloadDigest"]},
            {"artifactType": "audit-result", "digest": sha256_digest(audit)},
        ]
        def store(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
            envelope = seal_run_artifact(home, artifact_type=kind, profile_id=profile_id, run_id=run_id, payload=payload)
            path = write_run_artifact(home, envelope)
            artifacts[kind] = path
            outputs.append({"artifactType": kind, "path": _rel(home, path), "payloadDigest": envelope["payloadDigest"]})
            return envelope
        audit_envelope = store("audit-result", audit)
        coverage = {"schemaVersion": 1, "runId": run_id, "profileId": profile_id, "snapshotId": pin["snapshotId"], "policyDigest": pin["policyDigest"], "coverage": copy.deepcopy(audit["coverage"])}
        store("coverage", coverage)
        if plan is not None:
            store("build-plan", plan)
            inputs.append({"artifactType": "build-plan", "digest": sha256_digest(plan)})
        report = render_audit_report(home, audit_envelope)
        report_path = write_readable_report(home, profile_id=profile_id, run_id=run_id, report=report)
        artifacts["readable-report"] = report_path
        outputs.append({"artifactType": "readable-report", "path": _rel(home, report_path), "payloadDigest": sha256_digest(report.encode("utf-8"))})
        manifest = {
            "schemaVersion": 1,
            "runId": run_id,
            "profileId": profile_id,
            "snapshotId": pin["snapshotId"],
            "policyDigest": pin["policyDigest"],
            "command": "finalize",
            "startedAt": started_text,
            "completedAt": completed_text,
            "sourceCut": copy.deepcopy(pin["sourceCut"]),
            "projectEvidence": copy.deepcopy(audit["projectEvidence"]),
            "enforcementAuthorityLane": copy.deepcopy(audit["enforcementAuthorityLane"]),
            "inputs": sorted(inputs, key=lambda x: (x["artifactType"], x["digest"])),
            "outputs": sorted(outputs, key=lambda x: x["artifactType"]),
            "exitCode": int(code),
            "productionReady": ready,
        }
        manifest_envelope = store("run-manifest", manifest)
        post_run_assessment = build_post_run_assessment(
            audit_result=audit,
            run_manifest=manifest,
            run_manifest_digest=manifest_envelope["payloadDigest"],
            runtime_version=RUNTIME_VERSION,
        )
        store("post-run-assessment", post_run_assessment)
    except (RunArtifactIntegrityError, OSError, ValueError) as error:
        raise FinalizationError(f"Final evidence could not be sealed: {error}") from error
    return FinalizationResult(manifest, code, ready, post_run_assessment, artifacts)

def finalize_run(home: Path, *, profile_id: str, run_id: str, audit_result: dict[str, Any], build_plan: dict[str, Any] | None) -> FinalizationResult:
    """Finalize at trusted host time; public callers cannot inject freshness time."""
    try:
        persisted_manifest_envelope = read_run_artifact_if_present(
            home,
            profile_id=profile_id,
            run_id=run_id,
            artifact_type="run-manifest",
        )
    except RunArtifactIntegrityError as error:
        raise FinalizationError(
            f"Persisted run manifest cannot be verified for recovery: {error}"
        ) from error
    if persisted_manifest_envelope is not None:
        persisted_manifest = persisted_manifest_envelope["payload"]
        outputs = persisted_manifest.get("outputs")
        output_types = (
            [item.get("artifactType") for item in outputs]
            if isinstance(outputs, list) and all(isinstance(item, dict) for item in outputs)
            else []
        )
        expected_outputs = {"audit-result", "coverage", "readable-report"}
        if (
            len(output_types) != len(set(output_types))
            or set(output_types) not in {frozenset(expected_outputs), frozenset(expected_outputs | {"build-plan"})}
        ):
            raise FinalizationError("Persisted run manifest output set is invalid for recovery.")
        if (("build-plan" in output_types) != (build_plan is not None)):
            raise FinalizationError(
                "Retry build-plan presence differs from the persisted run manifest."
            )
        return _finalize_run_at(
            home,
            profile_id=profile_id,
            run_id=run_id,
            audit_result=audit_result,
            build_plan=build_plan,
            started_at=persisted_manifest.get("startedAt"),
            completed_at=persisted_manifest.get("completedAt"),
        )

    finalized_at = _utc_now()
    if not isinstance(finalized_at, datetime) or finalized_at.tzinfo is None:
        raise FinalizationError("Trusted finalization clock must be timezone-aware.")
    finalized_text = finalized_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return _finalize_run_at(
        home, profile_id=profile_id, run_id=run_id, audit_result=audit_result,
        build_plan=build_plan, started_at=finalized_text, completed_at=finalized_text,
    )

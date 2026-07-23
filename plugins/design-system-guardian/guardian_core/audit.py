"""Deterministic, read-only design-system and UX/accessibility audit evaluation."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import canonical_json_bytes, sha256_digest
from .clock import utc_now as _utc_now
from .contracts import ExitCode, ResolutionStatus
from .enforcement_authority import (
    EnforcementAuthorityIntegrityError,
    canonicalize_enforcement_authority_lane,
    enforcement_authority_lane,
)
from .project_binding import (
    ProjectBindingError,
    project_evidence_matches_binding,
    validate_project_binding,
    validate_project_evidence,
)
from .resolver import _resolve_verified_snapshot_identity
from .sentinels import SentinelIntegrityError, validate_sentinel
from .snapshot import SnapshotValidationError, classify_source_state


AUDIT_CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ADAPTER_KEYS = {
    "schemaVersion",
    "adapter",
    "supported",
    "configDigest",
    "sourceCut",
    "assessedFiles",
    "totalFiles",
    "categories",
    "diagnostics",
}
_CATEGORY_KEYS = {"status", "assessedItems", "totalItems"}
_DIAGNOSTIC_KEYS = {"diagnosticId", "category", "kind", "message", "evidence"}
_UX_CHECK_KEYS = {"checkId", "area", "status", "message", "evidence"}
_DESIGN_LANE_KEYS = {"status", "sourceCutDigest", "violations", "gaps", "sentinelCount", "resolutionSummary"}
_UX_LANE_KEYS = {"status", "checks"}
_COVERAGE_KEYS = {"schemaVersion", "adapter", "supported", "configDigest", "complete", "status", "categories", "assessedFiles", "totalFiles"}
_RESOLUTION_KEYS = {
    "schemaVersion",
    "status",
    "profileId",
    "snapshotId",
    "request",
    "selectedIdentity",
    "evidence",
    "sentinel",
}
_SOURCE_STATUSES = {
    ResolutionStatus.STALE.value,
    ResolutionStatus.SOURCE_UNAVAILABLE.value,
    ResolutionStatus.SOURCE_INCOMPLETE.value,
}
_COVERAGE_STATUSES = {
    ResolutionStatus.UNSUPPORTED.value,
    ResolutionStatus.NOT_ASSESSED.value,
}
_VIOLATION_STATUSES = {
    ResolutionStatus.MISSING.value,
    ResolutionStatus.AMBIGUOUS.value,
    ResolutionStatus.CONFLICT.value,
}
_SOURCE_STATE_TO_STATUS = {
    "stale": ResolutionStatus.STALE.value,
    "source_unavailable": ResolutionStatus.SOURCE_UNAVAILABLE.value,
    "source_incomplete": ResolutionStatus.SOURCE_INCOMPLETE.value,
}
_SOURCE_STATUS_ORDER = (
    ResolutionStatus.SOURCE_INCOMPLETE.value,
    ResolutionStatus.SOURCE_UNAVAILABLE.value,
    ResolutionStatus.STALE.value,
)
_UNTRUSTED_UX_RESULT = {
    "checkId": "guardian-trusted-ux-evaluator",
    "area": "ux_accessibility_evaluator",
    "status": "not_assessed",
    "message": "UX/accessibility was not assessed by a trusted host-owned evaluator.",
    "evidence": {
        "reason": "trusted_ux_evaluator_unavailable",
        "evaluatorVersion": None,
    },
}


class AuditIntegrityError(ValueError):
    """Raised when evidence cannot be bound to one verified run pin."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


@dataclass(frozen=True)
class AuditEvaluation:
    """Canonical audit payload plus its process-level outcome."""

    result: dict[str, Any]
    exit_code: ExitCode


def _require_plain_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditIntegrityError(f"{field} must be a non-negative integer.")
    return value


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditIntegrityError(f"{field} must be a non-empty string.")
    return value


def _sorted_objects(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((copy.deepcopy(item) for item in values), key=canonical_json_bytes)


def _validate_pin(run_pin: Any) -> dict[str, Any]:
    if not isinstance(run_pin, dict):
        raise AuditIntegrityError("Audit requires one verified run pin object.")
    for field in ("runId", "profileId", "snapshotId", "policyDigest", "sourceState"):
        _require_nonempty_string(run_pin.get(field), f"run pin {field}")
    if run_pin.get("schemaVersion") != 1:
        raise AuditIntegrityError("Audit supports only run pin schemaVersion 1.")
    if not _HEX_64.fullmatch(str(run_pin["snapshotId"])):
        raise AuditIntegrityError("Run pin snapshotId must be a lowercase SHA-256 digest.")
    if not _HEX_64.fullmatch(str(run_pin["policyDigest"])):
        raise AuditIntegrityError("Run pin policyDigest must be a lowercase SHA-256 digest.")
    if not isinstance(run_pin.get("sourceCut"), dict):
        raise AuditIntegrityError("Run pin sourceCut must be an object.")
    if run_pin["sourceState"] not in {
        "fresh",
        "offline_grace",
        "stale",
        "source_unavailable",
        "source_incomplete",
    }:
        raise AuditIntegrityError("Run pin sourceState is not a canonical source state.")
    try:
        validate_project_binding(run_pin.get("projectBinding"))
    except ProjectBindingError as error:
        raise AuditIntegrityError(f"Run pin intended project is invalid: {error}") from error
    return copy.deepcopy(run_pin)


def _validate_diagnostic(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _DIAGNOSTIC_KEYS:
        raise AuditIntegrityError("Adapter diagnostics have unknown or missing fields.")
    _require_nonempty_string(value.get("diagnosticId"), "diagnosticId")
    if value.get("category") not in AUDIT_CATEGORIES:
        raise AuditIntegrityError("Every diagnostic must use one exact audit category.")
    if value.get("kind") not in {"violation", "design_system_gap"}:
        raise AuditIntegrityError("Diagnostic kind must be violation or design_system_gap.")
    _require_nonempty_string(value.get("message"), "diagnostic message")
    if not isinstance(value.get("evidence"), dict):
        raise AuditIntegrityError("Diagnostic evidence must be an object.")
    if value["kind"] == "design_system_gap":
        evidence = value["evidence"]
        if not isinstance(evidence.get("approvedIdentity"), str) or not evidence["approvedIdentity"]:
            raise AuditIntegrityError(
                "A design-system gap must identify the inaccessible approved asset."
            )
        if evidence.get("requiredAction") != "request_design_system_change":
            raise AuditIntegrityError(
                "An inaccessible approved asset must request a design-system change."
            )
        if "replacement" in evidence:
            raise AuditIntegrityError("Audit evidence may not invent a replacement for an approved gap.")
    return copy.deepcopy(value)


def _validate_adapter(adapter_result: Any, source_cut: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(adapter_result, dict) or set(adapter_result) != _ADAPTER_KEYS:
        raise AuditIntegrityError("Adapter evidence has unknown or missing fields.")
    if adapter_result.get("schemaVersion") != 1:
        raise AuditIntegrityError("Audit supports only adapter evidence schemaVersion 1.")
    _require_nonempty_string(adapter_result.get("adapter"), "adapter")
    if not isinstance(adapter_result.get("supported"), bool):
        raise AuditIntegrityError("Adapter supported must be boolean.")
    config_digest = _require_nonempty_string(adapter_result.get("configDigest"), "configDigest")
    if not _HEX_64.fullmatch(config_digest):
        raise AuditIntegrityError("Adapter configDigest must be a lowercase SHA-256 digest.")
    if adapter_result.get("sourceCut") != source_cut:
        raise AuditIntegrityError("Adapter evidence is not bound to the pinned source-cut vector.")
    assessed_files = _require_plain_int(adapter_result.get("assessedFiles"), "assessedFiles")
    total_files = _require_plain_int(adapter_result.get("totalFiles"), "totalFiles")
    if assessed_files > total_files:
        raise AuditIntegrityError("assessedFiles cannot exceed totalFiles.")

    categories = adapter_result.get("categories")
    if not isinstance(categories, dict) or set(categories) != set(AUDIT_CATEGORIES):
        raise AuditIntegrityError("Coverage must explicitly report every exact audit category.")
    normalized_categories: dict[str, dict[str, Any]] = {}
    for category in AUDIT_CATEGORIES:
        evidence = categories[category]
        if not isinstance(evidence, dict) or set(evidence) != _CATEGORY_KEYS:
            raise AuditIntegrityError(f"Coverage for {category} has unknown or missing fields.")
        status = evidence.get("status")
        if status not in {"allowed", "unsupported", "not_assessed"}:
            raise AuditIntegrityError(f"Coverage for {category} has an invalid status.")
        assessed = _require_plain_int(evidence.get("assessedItems"), f"{category}.assessedItems")
        total = _require_plain_int(evidence.get("totalItems"), f"{category}.totalItems")
        if assessed > total:
            raise AuditIntegrityError(f"{category}.assessedItems cannot exceed totalItems.")
        if status == "allowed" and assessed != total:
            raise AuditIntegrityError(f"Allowed coverage for {category} must be complete.")
        normalized_categories[category] = {
            "status": status,
            "assessedItems": assessed,
            "totalItems": total,
        }

    diagnostics = adapter_result.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise AuditIntegrityError("Adapter diagnostics must be an array.")
    normalized_diagnostics = [_validate_diagnostic(item) for item in diagnostics]
    diagnostic_ids = [item["diagnosticId"] for item in normalized_diagnostics]
    if len(diagnostic_ids) != len(set(diagnostic_ids)):
        raise AuditIntegrityError("Diagnostic IDs must be unique within one audit.")

    complete = (
        adapter_result["supported"] is True
        and assessed_files == total_files
        and all(item["status"] == "allowed" for item in normalized_categories.values())
    )
    if complete:
        coverage_status = "allowed"
    elif adapter_result["supported"] is False or any(
        item["status"] == "unsupported" for item in normalized_categories.values()
    ):
        coverage_status = "unsupported"
    else:
        coverage_status = "not_assessed"
    coverage = {
        "schemaVersion": 1,
        "adapter": adapter_result["adapter"],
        "supported": adapter_result["supported"],
        "configDigest": config_digest,
        "complete": complete,
        "status": coverage_status,
        "categories": normalized_categories,
        "assessedFiles": assessed_files,
        "totalFiles": total_files,
    }
    return coverage, _sorted_objects(normalized_diagnostics)


def _validate_ux_checks(ux_checks: Any) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(ux_checks, list):
        raise AuditIntegrityError("UX/accessibility checks must be an array.")
    normalized: list[dict[str, Any]] = []
    for item in ux_checks:
        if not isinstance(item, dict) or set(item) != _UX_CHECK_KEYS:
            raise AuditIntegrityError("UX/accessibility checks have unknown or missing fields.")
        _require_nonempty_string(item.get("checkId"), "UX checkId")
        _require_nonempty_string(item.get("area"), "UX area")
        if item.get("status") not in {"allowed", "gap", "not_assessed"}:
            raise AuditIntegrityError("UX check status must be allowed, gap, or not_assessed.")
        _require_nonempty_string(item.get("message"), "UX message")
        if not isinstance(item.get("evidence"), dict):
            raise AuditIntegrityError("UX check evidence must be an object.")
        normalized.append(copy.deepcopy(item))
    check_ids = [item["checkId"] for item in normalized]
    if len(check_ids) != len(set(check_ids)):
        raise AuditIntegrityError("UX/accessibility check IDs must be unique.")
    # v0.1.0 has no trusted typed host-owned UX evaluator. Caller-authored
    # assertions are accepted only as structurally validated input and can
    # never certify this lane. Keep the canonical output idempotent so sealed
    # artifacts revalidate deterministically during finalization.
    return [copy.deepcopy(_UNTRUSTED_UX_RESULT)], ResolutionStatus.NOT_ASSESSED.value


def _authoritatively_resolve(
    resolutions: Any,
    *,
    pin: dict[str, Any],
    verified_snapshot: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    """Discard caller resolution claims and resolve each request from the pin."""

    # Preserve strict input-shape/integrity checks, but never use their status,
    # selected identity, evidence, or sentinel as authority.
    declared, _, _ = _validate_resolutions(
        resolutions,
        profile_id=pin["profileId"],
        snapshot_id=pin["snapshotId"],
        policy_digest=pin["policyDigest"],
    )
    if not declared:
        return _validate_resolutions(
            [],
            profile_id=pin["profileId"],
            snapshot_id=pin["snapshotId"],
            policy_digest=pin["policyDigest"],
        )
    if not isinstance(verified_snapshot, dict):
        raise AuditIntegrityError(
            "Audit resolutions require the verified pinned signed snapshot."
        )
    for field in ("profileId", "snapshotId", "sourceCut"):
        if verified_snapshot.get(field) != pin[field]:
            raise AuditIntegrityError(
                f"Verified snapshot {field} differs from the sealed run pin."
            )
    authoritative = [
        _resolve_verified_snapshot_identity(
            profile_id=pin["profileId"],
            snapshot=verified_snapshot,
            request=item["request"],
            policy_digest=pin["policyDigest"],
        )
        for item in declared
    ]
    return _validate_resolutions(
        authoritative,
        profile_id=pin["profileId"],
        snapshot_id=pin["snapshotId"],
        policy_digest=pin["policyDigest"],
    )


def _validate_resolutions(
    resolutions: Any,
    *,
    profile_id: str,
    snapshot_id: str,
    policy_digest: str,
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    if not isinstance(resolutions, list):
        raise AuditIntegrityError("Audit resolutions must be an array.")
    known_statuses = {member.value for member in ResolutionStatus}
    normalized: list[dict[str, Any]] = []
    counts = {status: 0 for status in sorted(known_statuses)}
    sentinel_count = 0
    for item in resolutions:
        if not isinstance(item, dict) or set(item) != _RESOLUTION_KEYS:
            raise AuditIntegrityError("Resolution evidence has unknown or missing fields.")
        if item.get("schemaVersion") != 1 or item.get("status") not in known_statuses:
            raise AuditIntegrityError("Resolution evidence has an invalid schema or status.")
        if item.get("profileId") != profile_id or item.get("snapshotId") != snapshot_id:
            raise AuditIntegrityError("Resolution evidence is not bound to the pinned run.")
        request = item.get("request")
        evidence = item.get("evidence")
        if not isinstance(request, dict) or not isinstance(evidence, dict):
            raise AuditIntegrityError("Resolution request and evidence must be objects.")
        if "policyDigest" in evidence and evidence["policyDigest"] != policy_digest:
            raise AuditIntegrityError("Resolution provenance crosses the immutable policy.")
        selected = item.get("selectedIdentity")
        if item["status"] == ResolutionStatus.ALLOWED.value:
            identity = request.get("identity")
            if not isinstance(identity, str) or not identity or selected != identity:
                raise AuditIntegrityError("Allowed resolution must select the exact requested identity.")
            if evidence.get("policyDigest") != policy_digest:
                raise AuditIntegrityError("Allowed resolution lacks exact policy provenance.")
        elif selected is not None:
            raise AuditIntegrityError("A non-allowed resolution cannot carry a selected identity.")
        sentinel = item.get("sentinel")
        if sentinel is not None:
            if item["status"] != ResolutionStatus.MISSING.value:
                raise AuditIntegrityError("Only a missing result may carry the fixed non-production sentinel.")
            try:
                normalized_sentinel = validate_sentinel(sentinel, policy_digest=policy_digest)
            except SentinelIntegrityError as error:
                raise AuditIntegrityError(str(error)) from error
            request_kind = request.get("kind")
            if request_kind == "icon":
                expected_kind = "icon"
            elif request_kind == "component":
                expected_kind = "component"
            elif request_kind == "token":
                expected_kind = {"color": "color", "typography": "textStyle"}.get(
                    request.get("tokenType"), "token"
                )
            else:
                raise AuditIntegrityError("Missing resolution has no exact sentinel-compatible request kind.")
            supplied_request_id = request.get("requestId")
            expected_request_id = (
                supplied_request_id
                if isinstance(supplied_request_id, str) and supplied_request_id
                else "guardian-" + sha256_digest(
                    {"profileId": profile_id, "snapshotId": snapshot_id, "request": request}
                )[:16]
            )
            if normalized_sentinel["kind"] != expected_kind or normalized_sentinel["requestId"] != expected_request_id:
                raise AuditIntegrityError("Sentinel is not bound to its exact missing request.")
            sentinel_count += 1
        elif item["status"] == ResolutionStatus.MISSING.value:
            raise AuditIntegrityError("Every proven missing result must carry its fixed sentinel.")
        counts[item["status"]] += 1
        normalized.append(copy.deepcopy(item))
    return _sorted_objects(normalized), counts, sentinel_count


def _select_exit_code(
    *,
    invalid: bool,
    source_blocked: bool,
    coverage_blocked: bool,
    violated: bool,
) -> ExitCode:
    if invalid:
        return ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY
    if source_blocked:
        return ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE
    if coverage_blocked:
        return ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE
    if violated:
        return ExitCode.VIOLATION_OR_SENTINEL
    return ExitCode.PASS


def derive_audit_exit_code(result: Any) -> ExitCode:
    """Recompute outcome from canonical evidence; never trust summaries or a claimed pass."""
    required = {"schemaVersion", "runId", "profileId", "snapshotId", "policyDigest", "analysisAttestationDigest", "projectEvidence", "enforcementAuthorityLane", "designSystemLane", "uxAccessibilityLane", "coverage", "resolutions", "productionReady"}
    if not isinstance(result, dict) or set(result) != required or result.get("schemaVersion") != 1:
        raise AuditIntegrityError("Audit result has unknown, missing, or invalid top-level fields.")
    for field in ("runId", "profileId"):
        _require_nonempty_string(result.get(field), f"audit {field}")
    for field in ("snapshotId", "policyDigest", "analysisAttestationDigest"):
        if not _HEX_64.fullmatch(_require_nonempty_string(result.get(field), f"audit {field}")):
            raise AuditIntegrityError(f"audit {field} must be a lowercase SHA-256 digest.")
    try:
        validate_project_evidence(result.get("projectEvidence"))
    except ProjectBindingError as error:
        raise AuditIntegrityError(f"Audit project evidence is invalid: {error}") from error
    try:
        enforcement_lane = canonicalize_enforcement_authority_lane(
            result.get("enforcementAuthorityLane")
        )
    except EnforcementAuthorityIntegrityError as error:
        raise AuditIntegrityError(f"Enforcement authority lane is invalid: {error}") from error
    if not isinstance(result.get("productionReady"), bool):
        raise AuditIntegrityError("Audit productionReady must be boolean.")
    design = result.get("designSystemLane")
    ux = result.get("uxAccessibilityLane")
    coverage = result.get("coverage")
    resolutions = result.get("resolutions")
    if not isinstance(design, dict) or set(design) != _DESIGN_LANE_KEYS:
        raise AuditIntegrityError("Design-system lane has unknown or missing fields.")
    if not isinstance(ux, dict) or set(ux) != _UX_LANE_KEYS:
        raise AuditIntegrityError("UX/accessibility lane has unknown or missing fields.")
    if not isinstance(coverage, dict) or set(coverage) != _COVERAGE_KEYS:
        raise AuditIntegrityError("Final coverage has unknown or missing fields.")
    if not isinstance(resolutions, list):
        raise AuditIntegrityError("Audit resolutions must be an array.")
    design_status = design.get("status")
    valid_design_statuses = {"allowed", "invalid", "stale", "source_unavailable", "source_incomplete", "unsupported", "not_assessed", "conflict"}
    if design_status not in valid_design_statuses or not _HEX_64.fullmatch(str(design.get("sourceCutDigest"))):
        raise AuditIntegrityError("Design-system lane status or source-cut digest is invalid.")
    violations = design.get("violations")
    gaps = design.get("gaps")
    if not isinstance(violations, list) or not isinstance(gaps, list):
        raise AuditIntegrityError("Final audit violations and gaps must be arrays.")
    normalized_violations = [_validate_diagnostic(item) for item in violations]
    normalized_gaps = [_validate_diagnostic(item) for item in gaps]
    if any(item["kind"] != "violation" for item in normalized_violations) or any(item["kind"] != "design_system_gap" for item in normalized_gaps):
        raise AuditIntegrityError("Diagnostics are stored in the wrong design-system lane.")
    if violations != _sorted_objects(normalized_violations) or gaps != _sorted_objects(normalized_gaps):
        raise AuditIntegrityError("Final diagnostics are not in canonical deterministic order.")
    diagnostic_ids = [item["diagnosticId"] for item in normalized_violations + normalized_gaps]
    if len(diagnostic_ids) != len(set(diagnostic_ids)):
        raise AuditIntegrityError("Final diagnostic IDs must be unique.")
    adapter_proxy = {
        "schemaVersion": coverage.get("schemaVersion"),
        "adapter": coverage.get("adapter"),
        "supported": coverage.get("supported"),
        "configDigest": coverage.get("configDigest"),
        "sourceCut": {},
        "assessedFiles": coverage.get("assessedFiles"),
        "totalFiles": coverage.get("totalFiles"),
        "categories": coverage.get("categories"),
        "diagnostics": normalized_violations + normalized_gaps,
    }
    normalized_coverage, _ = _validate_adapter(adapter_proxy, {})
    if coverage != normalized_coverage:
        raise AuditIntegrityError("Final coverage summary differs from its assessed evidence.")
    normalized_ux, ux_status = _validate_ux_checks(ux.get("checks"))
    if ux.get("status") != ux_status or ux.get("checks") != normalized_ux:
        raise AuditIntegrityError("UX/accessibility summary differs from its checks.")
    normalized_resolutions, resolution_counts, sentinel_count = _validate_resolutions(
        resolutions,
        profile_id=result["profileId"],
        snapshot_id=result["snapshotId"],
        policy_digest=result["policyDigest"],
    )
    if resolutions != normalized_resolutions:
        raise AuditIntegrityError("Final resolutions are not in canonical deterministic order.")
    if design.get("resolutionSummary") != resolution_counts:
        raise AuditIntegrityError("Resolution summary differs from exact resolution evidence.")
    if _require_plain_int(design.get("sentinelCount"), "designSystemLane.sentinelCount") != sentinel_count:
        raise AuditIntegrityError("Final audit sentinel count differs from resolution evidence.")
    statuses = {status for status, count in resolution_counts.items() if count}
    invalid = ResolutionStatus.INVALID.value in statuses
    source_statuses = statuses & _SOURCE_STATUSES
    if design_status in _SOURCE_STATUSES:
        source_statuses.add(design_status)
    coverage_resolution_statuses = statuses & _COVERAGE_STATUSES
    violated = bool(normalized_violations or normalized_gaps or sentinel_count or ux_status == "conflict" or statuses & _VIOLATION_STATUSES)
    if invalid:
        expected_design_status = ResolutionStatus.INVALID.value
    elif source_statuses:
        expected_design_status = next(status for status in _SOURCE_STATUS_ORDER if status in source_statuses)
    elif coverage["complete"] is not True:
        expected_design_status = coverage["status"]
    elif ResolutionStatus.UNSUPPORTED.value in coverage_resolution_statuses:
        expected_design_status = ResolutionStatus.UNSUPPORTED.value
    elif ResolutionStatus.NOT_ASSESSED.value in coverage_resolution_statuses:
        expected_design_status = ResolutionStatus.NOT_ASSESSED.value
    elif violated:
        expected_design_status = ResolutionStatus.CONFLICT.value
    else:
        expected_design_status = ResolutionStatus.ALLOWED.value
    if design_status != expected_design_status:
        raise AuditIntegrityError("Design-system lane status differs from its exact evidence.")
    return _select_exit_code(
        invalid=invalid,
        source_blocked=bool(source_statuses),
        coverage_blocked=(
            coverage["complete"] is not True or coverage["supported"] is not True
            or coverage["status"] != "allowed" or ux_status == "not_assessed"
            or enforcement_lane["status"] != "allowed"
            or bool(coverage_resolution_statuses)
        ),
        violated=violated,
    )


def evaluate_audit(
    *,
    run_pin: dict[str, Any],
    adapter_result: dict[str, Any],
    resolutions: list[dict[str, Any]],
    ux_checks: list[dict[str, Any]],
    project_evidence: dict[str, Any],
    verified_snapshot: dict[str, Any] | None = None,
    analysis_attestation_digest: str | None = None,
) -> AuditEvaluation:
    """Evaluate supplied evidence without writing source code or host state."""

    pin = _validate_pin(run_pin)
    try:
        normalized_project_evidence = project_evidence_matches_binding(
            project_evidence, pin["projectBinding"]
        )
    except ProjectBindingError as error:
        raise AuditIntegrityError(f"Audit project evidence is invalid: {error}") from error
    try:
        enforcement_lane = enforcement_authority_lane()
    except EnforcementAuthorityIntegrityError as error:
        raise AuditIntegrityError(f"Enforcement authority is invalid: {error}") from error
    if not isinstance(verified_snapshot, dict):
        raise AuditIntegrityError(
            "Audit requires the verified pinned signed snapshot even when no identities were requested."
        )
    for field in ("profileId", "snapshotId", "sourceCut"):
        if verified_snapshot.get(field) != pin[field]:
            raise AuditIntegrityError(
                f"Verified snapshot {field} differs from the sealed run pin."
            )
    try:
        current_source_state = classify_source_state(
            verified_snapshot,
            now=_utc_now(),
        )["state"]
    except SnapshotValidationError as error:
        raise AuditIntegrityError(
            f"Pinned snapshot freshness evidence is invalid: {error}"
        ) from error
    coverage, diagnostics = _validate_adapter(adapter_result, pin["sourceCut"])
    normalized_resolutions, resolution_counts, sentinel_count = _authoritatively_resolve(
        resolutions,
        pin=pin,
        verified_snapshot=verified_snapshot,
    )
    normalized_ux, ux_status = _validate_ux_checks(ux_checks)
    violations = [item for item in diagnostics if item["kind"] == "violation"]
    gaps = [item for item in diagnostics if item["kind"] == "design_system_gap"]

    resolution_statuses = {
        status for status, count in resolution_counts.items() if count > 0
    }
    invalid = ResolutionStatus.INVALID.value in resolution_statuses
    source_statuses = resolution_statuses & _SOURCE_STATUSES
    current_source_status = _SOURCE_STATE_TO_STATUS.get(current_source_state)
    if current_source_status is not None:
        source_statuses.add(current_source_status)
    source_blocked = bool(source_statuses)
    coverage_blocked = (
        coverage["complete"] is not True
        or ux_status == "not_assessed"
        or enforcement_lane["status"] != "allowed"
        or bool(resolution_statuses & _COVERAGE_STATUSES)
    )
    violated = bool(
        violations
        or gaps
        or sentinel_count
        or ux_status == "conflict"
        or resolution_statuses & _VIOLATION_STATUSES
    )
    exit_code = _select_exit_code(
        invalid=invalid,
        source_blocked=source_blocked,
        coverage_blocked=coverage_blocked,
        violated=violated,
    )

    if invalid:
        design_status = ResolutionStatus.INVALID.value
    elif source_blocked:
        design_status = next(
            status for status in _SOURCE_STATUS_ORDER if status in source_statuses
        )
    elif coverage["complete"] is not True:
        design_status = coverage["status"]
    elif ResolutionStatus.UNSUPPORTED.value in resolution_statuses:
        design_status = ResolutionStatus.UNSUPPORTED.value
    elif ResolutionStatus.NOT_ASSESSED.value in resolution_statuses:
        design_status = ResolutionStatus.NOT_ASSESSED.value
    elif violated:
        design_status = ResolutionStatus.CONFLICT.value
    else:
        design_status = ResolutionStatus.ALLOWED.value

    if analysis_attestation_digest is None:
        analysis_attestation_digest = "0" * 64
    if not isinstance(analysis_attestation_digest, str) or not _HEX_64.fullmatch(analysis_attestation_digest):
        raise AuditIntegrityError("Analysis attestation digest must be a lowercase SHA-256 digest.")

    result = {
        "schemaVersion": 1,
        "runId": pin["runId"],
        "profileId": pin["profileId"],
        "snapshotId": pin["snapshotId"],
        "policyDigest": pin["policyDigest"],
        "analysisAttestationDigest": analysis_attestation_digest,
        "projectEvidence": normalized_project_evidence,
        "enforcementAuthorityLane": enforcement_lane,
        "designSystemLane": {
            "status": design_status,
            "sourceCutDigest": sha256_digest(pin["sourceCut"]),
            "violations": _sorted_objects(violations),
            "gaps": _sorted_objects(gaps),
            "sentinelCount": sentinel_count,
            "resolutionSummary": resolution_counts,
        },
        "uxAccessibilityLane": {
            "status": ux_status,
            "checks": normalized_ux,
        },
        "coverage": coverage,
        "resolutions": normalized_resolutions,
        "productionReady": exit_code == ExitCode.PASS,
    }
    return AuditEvaluation(result=result, exit_code=exit_code)

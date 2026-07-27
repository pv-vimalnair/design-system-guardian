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
from .ux_evaluator import (
    REQUIRED_FLOW_AREAS,
    REQUIRED_SCREEN_AREAS,
    UX_EVALUATOR_CONTRACT_DIGEST,
)


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
_TRUSTED_UX_EVIDENCE_KEYS = {
    "scope",
    "targetDigest",
    "evidenceDigest",
    "reasonCode",
    "evaluatorDigest",
    "sourceCutDigest",
}
_TRUSTED_UX_MESSAGES = {
    "allowed": "UX/accessibility evidence satisfied the required check.",
    "gap": "UX/accessibility evidence did not satisfy the required check.",
    "not_assessed": "Required UX/accessibility evidence was unavailable for this check.",
}
_DESIGN_LANE_KEYS = {"status", "sourceCutDigest", "violations", "gaps", "sentinelCount", "resolutionSummary"}
_UX_LANE_KEYS = {"status", "checks"}
_USAGE_RULES_EVIDENCE_KEYS = {
    "schemaVersion",
    "status",
    "evaluatorId",
    "evaluatorContractDigest",
    "authorizationDigest",
    "ruleSnapshotId",
    "rulesDigest",
    "activeRuleIds",
    "assessedRuleIds",
    "violatedRuleIds",
    "informativeRuleIds",
    "notAssessed",
    "diagnostics",
}
_USAGE_RULES_LANE_KEYS = _USAGE_RULES_EVIDENCE_KEYS - {"schemaVersion"}
_USAGE_NOT_ASSESSED_KEYS = {"ruleId", "reasonCode"}
_USAGE_DIAGNOSTIC_KEYS = {
    "diagnosticId",
    "ruleId",
    "reasonCode",
    "inheritedDiagnosticId",
}
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
_AUDIT_V1_KEYS = {
    "schemaVersion",
    "runId",
    "profileId",
    "snapshotId",
    "policyDigest",
    "analysisAttestationDigest",
    "projectEvidence",
    "enforcementAuthorityLane",
    "designSystemLane",
    "uxAccessibilityLane",
    "coverage",
    "resolutions",
    "productionReady",
}
_AUDIT_V2_KEYS = _AUDIT_V1_KEYS | {"usageRulesLane"}
_USAGE_LANE_STATUSES = {
    "allowed",
    "conflict",
    "not_assessed",
    "unsupported",
    "invalid",
    "stale",
    "source_unavailable",
    "source_incomplete",
}
_USAGE_EVIDENCE_STATUSES = _USAGE_LANE_STATUSES - _SOURCE_STATUSES
_RULE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_REASON_CODE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_DIAGNOSTIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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


def _canonical_rule_ids(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise AuditIntegrityError(f"{field} must be an array.")
    if any(
        not isinstance(item, str)
        or len(item) > 127
        or not _RULE_ID.fullmatch(item)
        for item in value
    ):
        raise AuditIntegrityError(f"{field} contains an invalid rule ID.")
    if value != sorted(set(value)):
        raise AuditIntegrityError(f"{field} must be unique and sorted.")
    return list(value)


def _canonical_usage_rules(value: Any, *, lane: bool) -> dict[str, Any]:
    expected_keys = _USAGE_RULES_LANE_KEYS if lane else _USAGE_RULES_EVIDENCE_KEYS
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise AuditIntegrityError("Usage Rules evidence has unknown or missing fields.")
    if not lane and value.get("schemaVersion") != 1:
        raise AuditIntegrityError("Usage Rules evidence schemaVersion must be 1.")
    statuses = _USAGE_LANE_STATUSES if lane else _USAGE_EVIDENCE_STATUSES
    status = value.get("status")
    if status not in statuses:
        raise AuditIntegrityError("Usage Rules status is outside the canonical contract.")
    if value.get("evaluatorId") != "guardian-flutter-usage-rules-v2":
        raise AuditIntegrityError("Usage Rules evidence uses another evaluator.")
    for field in (
        "evaluatorContractDigest",
        "authorizationDigest",
        "ruleSnapshotId",
        "rulesDigest",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            raise AuditIntegrityError(
                f"Usage Rules {field} must be a lowercase SHA-256 digest."
            )

    active = _canonical_rule_ids(value.get("activeRuleIds"), "activeRuleIds")
    assessed = _canonical_rule_ids(value.get("assessedRuleIds"), "assessedRuleIds")
    violated = _canonical_rule_ids(value.get("violatedRuleIds"), "violatedRuleIds")
    informative = _canonical_rule_ids(
        value.get("informativeRuleIds"), "informativeRuleIds"
    )

    raw_not_assessed = value.get("notAssessed")
    if not isinstance(raw_not_assessed, list):
        raise AuditIntegrityError("notAssessed must be an array.")
    not_assessed: list[dict[str, str]] = []
    for item in raw_not_assessed:
        if not isinstance(item, dict) or set(item) != _USAGE_NOT_ASSESSED_KEYS:
            raise AuditIntegrityError(
                "Usage Rules notAssessed entries have unknown or missing fields."
            )
        rule_id = item.get("ruleId")
        reason_code = item.get("reasonCode")
        if (
            not isinstance(rule_id, str)
            or len(rule_id) > 127
            or not _RULE_ID.fullmatch(rule_id)
        ):
            raise AuditIntegrityError("Usage Rules notAssessed ruleId is invalid.")
        if (
            not isinstance(reason_code, str)
            or len(reason_code) > 127
            or not _REASON_CODE.fullmatch(reason_code)
        ):
            raise AuditIntegrityError("Usage Rules notAssessed reasonCode is invalid.")
        not_assessed.append({"ruleId": rule_id, "reasonCode": reason_code})
    expected_not_assessed = sorted(not_assessed, key=canonical_json_bytes)
    if raw_not_assessed != expected_not_assessed:
        raise AuditIntegrityError("Usage Rules notAssessed must be unique and sorted.")
    not_assessed_ids = [item["ruleId"] for item in not_assessed]
    if len(not_assessed_ids) != len(set(not_assessed_ids)):
        raise AuditIntegrityError("A Usage Rules rule may have only one not-assessed reason.")

    raw_diagnostics = value.get("diagnostics")
    if not isinstance(raw_diagnostics, list):
        raise AuditIntegrityError("Usage Rules diagnostics must be an array.")
    diagnostics: list[dict[str, str]] = []
    for item in raw_diagnostics:
        if not isinstance(item, dict) or set(item) != _USAGE_DIAGNOSTIC_KEYS:
            raise AuditIntegrityError(
                "Usage Rules diagnostics have unknown or missing fields."
            )
        diagnostic_id = item.get("diagnosticId")
        inherited_id = item.get("inheritedDiagnosticId")
        rule_id = item.get("ruleId")
        reason_code = item.get("reasonCode")
        if (
            not isinstance(diagnostic_id, str)
            or not _DIAGNOSTIC_ID.fullmatch(diagnostic_id)
            or not isinstance(inherited_id, str)
            or not _DIAGNOSTIC_ID.fullmatch(inherited_id)
        ):
            raise AuditIntegrityError("Usage Rules diagnostic identity is invalid.")
        if (
            not isinstance(rule_id, str)
            or len(rule_id) > 127
            or not _RULE_ID.fullmatch(rule_id)
            or not isinstance(reason_code, str)
            or len(reason_code) > 127
            or not _REASON_CODE.fullmatch(reason_code)
        ):
            raise AuditIntegrityError("Usage Rules diagnostic rule or reason is invalid.")
        diagnostics.append(
            {
                "diagnosticId": diagnostic_id,
                "ruleId": rule_id,
                "reasonCode": reason_code,
                "inheritedDiagnosticId": inherited_id,
            }
        )
    expected_diagnostics = sorted(diagnostics, key=canonical_json_bytes)
    if raw_diagnostics != expected_diagnostics:
        raise AuditIntegrityError("Usage Rules diagnostics must be unique and sorted.")
    diagnostic_ids = [item["diagnosticId"] for item in diagnostics]
    inherited_ids = [item["inheritedDiagnosticId"] for item in diagnostics]
    if (
        len(diagnostic_ids) != len(set(diagnostic_ids))
        or len(inherited_ids) != len(set(inherited_ids))
    ):
        raise AuditIntegrityError("Usage Rules diagnostic identities must be unique.")

    active_set = set(active)
    assessed_set = set(assessed)
    violated_set = set(violated)
    not_assessed_set = set(not_assessed_ids)
    informative_set = set(informative)
    if not assessed_set <= active_set or not violated_set <= assessed_set:
        raise AuditIntegrityError("Usage Rules assessed and violated sets are not subsets.")
    if active_set != assessed_set | (not_assessed_set & active_set):
        raise AuditIntegrityError(
            "Every active Usage Rules rule must be assessed or explicitly not assessed."
        )
    if assessed_set & not_assessed_set:
        raise AuditIntegrityError("A Usage Rules rule cannot be assessed and not assessed.")
    if informative_set & (active_set | not_assessed_set):
        raise AuditIntegrityError("Informative rules cannot enter a gating Usage Rules set.")
    if {item["ruleId"] for item in diagnostics} != violated_set:
        raise AuditIntegrityError(
            "Usage Rules diagnostics differ from the exact violated rule IDs."
        )

    if status not in _SOURCE_STATUSES and status != "invalid":
        expected_status = (
            "conflict"
            if violated
            else "unsupported"
            if status == "unsupported"
            else "not_assessed"
            if not_assessed
            else "allowed"
        )
        if status != expected_status:
            raise AuditIntegrityError("Usage Rules status differs from its exact evidence.")
        if status == "unsupported" and (assessed or diagnostics):
            raise AuditIntegrityError(
                "Unsupported Usage Rules evidence cannot claim assessed rules."
            )

    normalized = {
        key: copy.deepcopy(value[key])
        for key in _USAGE_RULES_LANE_KEYS
    }
    if not lane:
        normalized["schemaVersion"] = 1
    return normalized


def canonical_usage_rules_evidence(value: Any) -> dict[str, Any]:
    """Validate the adapter-owned v2 evidence interface without trusting summaries."""

    return _canonical_usage_rules(value, lane=False)


def _inherited_usage_diagnostic_ids(design_lane: dict[str, Any]) -> list[str]:
    violations = design_lane.get("violations")
    if not isinstance(violations, list):
        raise AuditIntegrityError("Design-system violations must be an array.")
    identifiers: list[str] = []
    for item in violations:
        evidence = item.get("evidence") if isinstance(item, dict) else None
        if isinstance(evidence, dict) and evidence.get("code") == "guardian_usage_rule":
            identifier = item.get("diagnosticId")
            if not isinstance(identifier, str):
                raise AuditIntegrityError(
                    "Inherited Usage Rules diagnostic identity is invalid."
                )
            identifiers.append(identifier)
    return sorted(identifiers)


def _assert_usage_rules_agreement(
    lane: dict[str, Any],
    *,
    design_lane: dict[str, Any],
    coverage: dict[str, Any],
) -> None:
    expected_inherited = sorted(
        item["inheritedDiagnosticId"] for item in lane["diagnostics"]
    )
    if _inherited_usage_diagnostic_ids(design_lane) != expected_inherited:
        raise AuditIntegrityError(
            "Usage Rules diagnostics disagree with the inherited design-system projection."
        )
    categories = coverage.get("categories")
    components = categories.get("components") if isinstance(categories, dict) else None
    component_status = components.get("status") if isinstance(components, dict) else None
    status = lane["status"]
    if status in _SOURCE_STATUSES:
        if design_lane.get("status") != status:
            raise AuditIntegrityError(
                "Usage Rules source status disagrees with the inherited projection."
            )
        return
    if status == "invalid":
        if design_lane.get("status") != "invalid":
            raise AuditIntegrityError(
                "Invalid Usage Rules evidence disagrees with the inherited projection."
            )
        return
    if status == "conflict":
        if component_status not in {"allowed", "not_assessed", "unsupported"}:
            raise AuditIntegrityError(
                "Usage Rules conflict has invalid inherited coverage."
            )
    else:
        expected_coverage = {
            "allowed": "allowed",
            "not_assessed": "not_assessed",
            "unsupported": "unsupported",
        }[status]
        if component_status != expected_coverage:
            raise AuditIntegrityError(
                "Usage Rules coverage disagrees with the inherited design-system projection."
            )
    if status == "conflict" and design_lane.get("status") != "conflict":
        raise AuditIntegrityError(
            "Usage Rules conflict disagrees with the inherited design-system projection."
        )


def _project_usage_rules_lane(
    evidence: Any,
    *,
    source_status: str | None,
    design_lane: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    normalized = canonical_usage_rules_evidence(evidence)
    lane = {
        key: copy.deepcopy(normalized[key])
        for key in _USAGE_RULES_LANE_KEYS
    }
    if lane["status"] != "invalid" and source_status in _SOURCE_STATUSES:
        lane["status"] = source_status
    _assert_usage_rules_agreement(
        lane,
        design_lane=design_lane,
        coverage=coverage,
    )
    return lane


def project_usage_rules_lane(
    evidence: Any,
    *,
    design_system_lane: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    """Project exact runner evidence into the additive audit-result v2 lane."""

    if not isinstance(design_system_lane, dict) or not isinstance(coverage, dict):
        raise AuditIntegrityError(
            "Usage Rules projection requires canonical design-system and coverage lanes."
        )
    design_status = design_system_lane.get("status")
    return _project_usage_rules_lane(
        evidence,
        source_status=(design_status if design_status in _SOURCE_STATUSES else None),
        design_lane=design_system_lane,
        coverage=coverage,
    )


def _validate_usage_rules_lane(
    value: Any,
    *,
    design_lane: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    lane = _canonical_usage_rules(value, lane=True)
    _assert_usage_rules_agreement(
        lane,
        design_lane=design_lane,
        coverage=coverage,
    )
    return lane


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
    if not isinstance(adapter_result, dict):
        raise AuditIntegrityError("Adapter evidence has unknown or missing fields.")
    keys = set(adapter_result)
    has_usage_rules = keys == _ADAPTER_KEYS | {"usageRulesEvidence"}
    if keys != _ADAPTER_KEYS and not has_usage_rules:
        raise AuditIntegrityError("Adapter evidence has unknown or missing fields.")
    if adapter_result.get("schemaVersion") != 1:
        raise AuditIntegrityError("Audit supports only adapter evidence schemaVersion 1.")
    _require_nonempty_string(adapter_result.get("adapter"), "adapter")
    if has_usage_rules:
        if adapter_result["adapter"] != "flutter":
            raise AuditIntegrityError(
                "Only Flutter adapter evidence may contain Usage Rules evidence."
            )
        canonical_usage_rules_evidence(adapter_result["usageRulesEvidence"])
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


def adapter_audit_projection(
    adapter_result: Any,
    source_cut: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return the fail-closed audit projection for one normalized adapter result.

    Portable Figma observations are caller-carried local evidence in v0.3.3.
    Exact violations remain useful, but a clean observation cannot authorize an
    ``allowed`` coverage claim until a protected host receipt exists.
    """

    coverage, diagnostics = _validate_adapter(adapter_result, source_cut)
    if coverage["adapter"] != "figma":
        return coverage, diagnostics

    categories = copy.deepcopy(coverage["categories"])
    for evidence in categories.values():
        if evidence["status"] == "allowed":
            evidence["status"] = "not_assessed"
    coverage["categories"] = categories
    coverage["complete"] = False
    coverage["status"] = (
        "unsupported"
        if coverage["supported"] is False
        or any(item["status"] == "unsupported" for item in categories.values())
        else "not_assessed"
    )
    return coverage, diagnostics


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


def _validate_trusted_ux_checks(
    ux_checks: Any,
    *,
    source_cut_digest: str,
) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(source_cut_digest, str) or not _HEX_64.fullmatch(source_cut_digest):
        raise AuditIntegrityError("Trusted UX checks require the pinned source-cut digest.")
    if not isinstance(ux_checks, list) or not ux_checks:
        raise AuditIntegrityError("Trusted final UX evaluation must contain checks.")
    normalized: list[dict[str, Any]] = []
    check_ids: set[str] = set()
    covered: set[tuple[str, str]] = set()
    targets: dict[str, dict[str, set[str]]] = {"screen": {}, "flow": {}}
    for item in ux_checks:
        if not isinstance(item, dict) or set(item) != _UX_CHECK_KEYS:
            raise AuditIntegrityError("Trusted UX checks have unknown or missing fields.")
        check_id = _require_nonempty_string(item.get("checkId"), "trusted UX checkId")
        if check_id in check_ids:
            raise AuditIntegrityError("Trusted UX check IDs must be unique.")
        check_ids.add(check_id)
        status = item.get("status")
        if status not in _TRUSTED_UX_MESSAGES or item.get("message") != _TRUSTED_UX_MESSAGES[status]:
            raise AuditIntegrityError("Trusted UX check status or fixed message is invalid.")
        evidence = item.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != _TRUSTED_UX_EVIDENCE_KEYS:
            raise AuditIntegrityError("Trusted UX check evidence has unknown or missing fields.")
        scope = evidence.get("scope")
        if scope not in {"screen", "flow"}:
            raise AuditIntegrityError("Trusted UX check scope is invalid.")
        target_digest = evidence.get("targetDigest")
        if not isinstance(target_digest, str) or not _HEX_64.fullmatch(target_digest):
            raise AuditIntegrityError("Trusted UX targetDigest must be a SHA-256 digest.")
        if evidence.get("evaluatorDigest") != UX_EVALUATOR_CONTRACT_DIGEST:
            raise AuditIntegrityError("Trusted UX check uses another evaluator contract.")
        if evidence.get("sourceCutDigest") != source_cut_digest:
            raise AuditIntegrityError("Trusted UX check differs from the pinned source cut.")
        reason_code = evidence.get("reasonCode")
        evidence_digest = evidence.get("evidenceDigest")
        expected_reason = None if status == "allowed" else f"ux_{scope}_{'gap' if status == 'gap' else 'not_assessed'}"
        if reason_code != expected_reason:
            raise AuditIntegrityError("Trusted UX check has the wrong fixed reason code.")
        if status == "not_assessed":
            if evidence_digest is not None:
                raise AuditIntegrityError("Unassessed UX check cannot claim evidence.")
        elif not isinstance(evidence_digest, str) or not _HEX_64.fullmatch(evidence_digest):
            raise AuditIntegrityError("Assessed UX check requires an evidence digest.")
        area = _require_nonempty_string(item.get("area"), "trusted UX area")
        required = REQUIRED_SCREEN_AREAS if scope == "screen" else REQUIRED_FLOW_AREAS
        if area not in required:
            raise AuditIntegrityError("Trusted UX check area is outside its scope.")
        coverage_key = (target_digest, area)
        if coverage_key in covered:
            raise AuditIntegrityError("Trusted UX evaluation repeats a target area.")
        covered.add(coverage_key)
        targets[scope].setdefault(target_digest, set()).add(area)
        normalized.append(copy.deepcopy(item))
    if not targets["screen"] or len(targets["flow"]) != 1:
        raise AuditIntegrityError("Trusted final UX evaluation must cover screens and one flow.")
    for scope, scoped_targets in targets.items():
        required = set(REQUIRED_SCREEN_AREAS if scope == "screen" else REQUIRED_FLOW_AREAS)
        if any(areas != required for areas in scoped_targets.values()):
            raise AuditIntegrityError("Trusted UX target coverage is incomplete.")
    # The built-in portable evaluator validates structure and detects proven
    # gaps, but its observations remain caller-carried local evidence. Preserve
    # every gap while canonicalizing positive claims to not_assessed.
    for item in normalized:
        if item["status"] != "allowed":
            continue
        scope = item["evidence"]["scope"]
        item["status"] = "not_assessed"
        item["message"] = _TRUSTED_UX_MESSAGES["not_assessed"]
        item["evidence"]["evidenceDigest"] = None
        item["evidence"]["reasonCode"] = f"ux_{scope}_not_assessed"
    normalized = _sorted_objects(normalized)
    if any(item["status"] == "gap" for item in normalized):
        return normalized, ResolutionStatus.CONFLICT.value
    if any(item["status"] == "not_assessed" for item in normalized):
        return normalized, ResolutionStatus.NOT_ASSESSED.value
    return normalized, ResolutionStatus.ALLOWED.value


def _validate_final_ux_checks(
    ux_checks: Any,
    *,
    source_cut_digest: str,
) -> tuple[list[dict[str, Any]], str]:
    if (
        isinstance(ux_checks, list)
        and len(ux_checks) == 1
        and isinstance(ux_checks[0], dict)
        and ux_checks[0].get("checkId") == _UNTRUSTED_UX_RESULT["checkId"]
    ):
        return _validate_ux_checks(ux_checks)
    return _validate_trusted_ux_checks(
        ux_checks,
        source_cut_digest=source_cut_digest,
    )


def canonical_untrusted_ux_lane() -> dict[str, Any]:
    """Return the sole valid UX lane for an attestation without UX evidence."""

    return {
        "status": ResolutionStatus.NOT_ASSESSED.value,
        "checks": [copy.deepcopy(_UNTRUSTED_UX_RESULT)],
    }


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
    if violated:
        return ExitCode.VIOLATION_OR_SENTINEL
    if coverage_blocked:
        return ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE
    return ExitCode.PASS


def derive_audit_exit_code(result: Any) -> ExitCode:
    """Recompute outcome from canonical evidence; never trust summaries or a claimed pass."""
    if not isinstance(result, dict):
        raise AuditIntegrityError("Audit result must be an object.")
    schema_version = result.get("schemaVersion")
    required = (
        _AUDIT_V1_KEYS
        if schema_version == 1
        else _AUDIT_V2_KEYS
        if schema_version == 2
        else set()
    )
    if not required or set(result) != required:
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
    normalized_coverage, _ = adapter_audit_projection(adapter_proxy, {})
    if coverage != normalized_coverage:
        raise AuditIntegrityError("Final coverage summary differs from its assessed evidence.")
    normalized_ux, ux_status = _validate_final_ux_checks(
        ux.get("checks"),
        source_cut_digest=str(design.get("sourceCutDigest")),
    )
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
    design_violated = bool(
        normalized_violations
        or normalized_gaps
        or sentinel_count
        or statuses & _VIOLATION_STATUSES
    )
    ux_violated = ux_status == "conflict"
    violated = design_violated or ux_violated
    if invalid:
        expected_design_status = ResolutionStatus.INVALID.value
    elif source_statuses:
        expected_design_status = next(status for status in _SOURCE_STATUS_ORDER if status in source_statuses)
    elif design_violated:
        expected_design_status = ResolutionStatus.CONFLICT.value
    elif coverage["complete"] is not True:
        expected_design_status = coverage["status"]
    elif ResolutionStatus.UNSUPPORTED.value in coverage_resolution_statuses:
        expected_design_status = ResolutionStatus.UNSUPPORTED.value
    elif ResolutionStatus.NOT_ASSESSED.value in coverage_resolution_statuses:
        expected_design_status = ResolutionStatus.NOT_ASSESSED.value
    else:
        expected_design_status = ResolutionStatus.ALLOWED.value
    if design_status != expected_design_status:
        raise AuditIntegrityError("Design-system lane status differs from its exact evidence.")

    coverage_blocked = (
        coverage["complete"] is not True
        or coverage["supported"] is not True
        or coverage["status"] != "allowed"
        or ux_status == "not_assessed"
        or enforcement_lane["status"] != "allowed"
        or bool(coverage_resolution_statuses)
    )
    if schema_version == 2:
        usage_lane = _validate_usage_rules_lane(
            result.get("usageRulesLane"),
            design_lane=design,
            coverage=coverage,
        )
        invalid = invalid or usage_lane["status"] == "invalid"
        if usage_lane["status"] in _SOURCE_STATUSES:
            source_statuses.add(usage_lane["status"])
        violated = violated or usage_lane["status"] == "conflict"
        coverage_blocked = coverage_blocked or usage_lane["status"] in {
            "not_assessed",
            "unsupported",
        }

    exit_code = _select_exit_code(
        invalid=invalid,
        source_blocked=bool(source_statuses),
        coverage_blocked=coverage_blocked,
        violated=violated,
    )
    if schema_version == 2 and result["productionReady"] is not (
        exit_code == ExitCode.PASS
    ):
        raise AuditIntegrityError(
            "Audit productionReady differs from the complete v2 lane evidence."
        )
    return exit_code


def project_audit_result_v1(result: Any) -> dict[str, Any]:
    """Return the exact inherited v1 projection after validating current evidence."""

    derive_audit_exit_code(result)
    projected = copy.deepcopy(result)
    if projected["schemaVersion"] == 2:
        projected["schemaVersion"] = 1
        projected.pop("usageRulesLane")
    return projected


def evaluate_audit(
    *,
    run_pin: dict[str, Any],
    adapter_result: dict[str, Any],
    resolutions: list[dict[str, Any]],
    ux_checks: list[dict[str, Any]],
    project_evidence: dict[str, Any],
    verified_snapshot: dict[str, Any] | None = None,
    analysis_attestation_digest: str | None = None,
    trusted_ux_checks: list[dict[str, Any]] | None = None,
    usage_rules_evidence: dict[str, Any] | None = None,
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
    coverage, diagnostics = adapter_audit_projection(
        adapter_result, pin["sourceCut"]
    )
    embedded_usage_evidence = adapter_result.get("usageRulesEvidence")
    if embedded_usage_evidence is not None:
        normalized_embedded = canonical_usage_rules_evidence(
            embedded_usage_evidence
        )
        if usage_rules_evidence is None:
            usage_rules_evidence = normalized_embedded
        elif canonical_usage_rules_evidence(usage_rules_evidence) != normalized_embedded:
            raise AuditIntegrityError(
                "Explicit Usage Rules evidence differs from the normalized adapter evidence."
            )
    normalized_resolutions, resolution_counts, sentinel_count = _authoritatively_resolve(
        resolutions,
        pin=pin,
        verified_snapshot=verified_snapshot,
    )
    if trusted_ux_checks is None:
        normalized_ux, ux_status = _validate_ux_checks(ux_checks)
    else:
        normalized_ux, ux_status = _validate_trusted_ux_checks(
            trusted_ux_checks,
            source_cut_digest=sha256_digest(pin["sourceCut"]),
        )
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
    design_violated = bool(
        violations
        or gaps
        or sentinel_count
        or resolution_statuses & _VIOLATION_STATUSES
    )
    ux_violated = ux_status == "conflict"
    violated = design_violated or ux_violated

    if invalid:
        design_status = ResolutionStatus.INVALID.value
    elif source_blocked:
        design_status = next(
            status for status in _SOURCE_STATUS_ORDER if status in source_statuses
        )
    elif design_violated:
        design_status = ResolutionStatus.CONFLICT.value
    elif coverage["complete"] is not True:
        design_status = coverage["status"]
    elif ResolutionStatus.UNSUPPORTED.value in resolution_statuses:
        design_status = ResolutionStatus.UNSUPPORTED.value
    elif ResolutionStatus.NOT_ASSESSED.value in resolution_statuses:
        design_status = ResolutionStatus.NOT_ASSESSED.value
    else:
        design_status = ResolutionStatus.ALLOWED.value

    if analysis_attestation_digest is None:
        analysis_attestation_digest = "0" * 64
    if not isinstance(analysis_attestation_digest, str) or not _HEX_64.fullmatch(analysis_attestation_digest):
        raise AuditIntegrityError("Analysis attestation digest must be a lowercase SHA-256 digest.")

    design_lane = {
        "status": design_status,
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "violations": _sorted_objects(violations),
        "gaps": _sorted_objects(gaps),
        "sentinelCount": sentinel_count,
        "resolutionSummary": resolution_counts,
    }
    usage_lane = None
    if usage_rules_evidence is not None:
        usage_lane = _project_usage_rules_lane(
            usage_rules_evidence,
            source_status=(
                design_status if design_status in _SOURCE_STATUSES else None
            ),
            design_lane=design_lane,
            coverage=coverage,
        )
        invalid = invalid or usage_lane["status"] == "invalid"
        source_blocked = source_blocked or usage_lane["status"] in _SOURCE_STATUSES
        violated = violated or usage_lane["status"] == "conflict"
        coverage_blocked = coverage_blocked or usage_lane["status"] in {
            "not_assessed",
            "unsupported",
        }
    exit_code = _select_exit_code(
        invalid=invalid,
        source_blocked=source_blocked,
        coverage_blocked=coverage_blocked,
        violated=violated,
    )

    result = {
        "schemaVersion": 2 if usage_lane is not None else 1,
        "runId": pin["runId"],
        "profileId": pin["profileId"],
        "snapshotId": pin["snapshotId"],
        "policyDigest": pin["policyDigest"],
        "analysisAttestationDigest": analysis_attestation_digest,
        "projectEvidence": normalized_project_evidence,
        "enforcementAuthorityLane": enforcement_lane,
        "designSystemLane": design_lane,
        "uxAccessibilityLane": {
            "status": ux_status,
            "checks": normalized_ux,
        },
        "coverage": coverage,
        "resolutions": normalized_resolutions,
        "productionReady": exit_code == ExitCode.PASS,
    }
    if usage_lane is not None:
        result["usageRulesLane"] = usage_lane
    return AuditEvaluation(result=result, exit_code=exit_code)

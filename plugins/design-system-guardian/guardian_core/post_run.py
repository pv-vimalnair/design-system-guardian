"""Deterministic, privacy-preserving assessment of one verified finalized run."""

from __future__ import annotations

import copy
import re
from typing import Any

from .audit import AuditIntegrityError, derive_audit_exit_code
from .canonical import sha256_digest


ALLOWED_ATTRIBUTIONS = {
    "project_implementation",
    "design_system",
    "source",
    "project_configuration",
    "capability_candidate",
    "plugin_candidate",
}

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_RUNTIME_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_IDENTITY_FIELDS = ("runId", "profileId", "snapshotId", "policyDigest")
_DESIGN_STATUSES = {
    "allowed",
    "invalid",
    "stale",
    "source_unavailable",
    "source_incomplete",
    "unsupported",
    "not_assessed",
    "conflict",
}
_UX_STATUSES = {"allowed", "conflict", "not_assessed"}
_COVERAGE_STATUSES = {"allowed", "unsupported", "not_assessed"}
_ENFORCEMENT_STATUSES = {"allowed", "not_assessed"}
_USAGE_STATUSES = {
    "allowed",
    "conflict",
    "not_assessed",
    "unsupported",
    "invalid",
    "stale",
    "source_unavailable",
    "source_incomplete",
}
_RESOLUTION_STATUSES = (
    "allowed",
    "missing",
    "ambiguous",
    "conflict",
    "invalid",
    "unsupported",
    "stale",
    "source_unavailable",
    "source_incomplete",
    "not_assessed",
)
_RUN_STATUSES = {
    0: "passed",
    1: "violation",
    2: "invalid",
    3: "source_blocked",
    4: "unsupported",
}
_RESOLUTION_REASONS = {
    "missing": ("resolution_missing", "design_system"),
    "ambiguous": ("resolution_ambiguous", "design_system"),
    "conflict": ("resolution_conflict", "design_system"),
    "invalid": ("resolution_invalid", "project_implementation"),
    "unsupported": ("resolution_unsupported", "capability_candidate"),
    "stale": ("resolution_stale", "source"),
    "source_unavailable": ("resolution_source_unavailable", "source"),
    "source_incomplete": ("resolution_source_incomplete", "source"),
    "not_assessed": ("resolution_not_assessed", "project_configuration"),
}


class PostRunAssessmentIntegrityError(ValueError):
    """Raised when supposedly verified final-run evidence is inconsistent."""


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PostRunAssessmentIntegrityError(f"{field} must be an object.")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise PostRunAssessmentIntegrityError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _status(value: Any, allowed: set[str], field: str) -> str:
    if value not in allowed:
        raise PostRunAssessmentIntegrityError(f"{field} has an unsupported status.")
    return value


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PostRunAssessmentIntegrityError(f"{field} must be a non-negative integer.")
    return value


def build_post_run_assessment(
    *,
    audit_result: dict[str, Any],
    run_manifest: dict[str, Any],
    run_manifest_digest: str,
    runtime_version: str,
) -> dict[str, Any]:
    """Reduce verified final evidence to stable statuses, counts, and reason codes."""

    audit = _object(audit_result, "audit_result")
    manifest = _object(run_manifest, "run_manifest")
    schema_version = audit.get("schemaVersion")
    if schema_version not in {1, 2} or manifest.get("schemaVersion") != schema_version:
        raise PostRunAssessmentIntegrityError(
            "Final evidence schemaVersion must be the same supported version."
        )
    is_v2 = schema_version == 2
    for field in _IDENTITY_FIELDS:
        if audit.get(field) != manifest.get(field):
            raise PostRunAssessmentIntegrityError(f"Final evidence {field} values differ.")
        if not isinstance(audit.get(field), str) or not audit[field]:
            raise PostRunAssessmentIntegrityError(f"Final evidence {field} must be non-empty text.")
    if not _RUN_ID.fullmatch(audit["runId"]):
        raise PostRunAssessmentIntegrityError("Final evidence runId is malformed.")
    if not _PROFILE_ID.fullmatch(audit["profileId"]):
        raise PostRunAssessmentIntegrityError("Final evidence profileId is malformed.")
    snapshot_id = _digest(audit["snapshotId"], "snapshotId")
    policy_digest = _digest(audit["policyDigest"], "policyDigest")
    manifest_digest = _digest(run_manifest_digest, "run_manifest_digest")
    if not isinstance(runtime_version, str) or not _RUNTIME_VERSION.fullmatch(runtime_version):
        raise PostRunAssessmentIntegrityError("runtime_version must be a stable version identifier.")

    exit_code = manifest.get("exitCode")
    if isinstance(exit_code, bool) or exit_code not in _RUN_STATUSES:
        raise PostRunAssessmentIntegrityError("Run manifest exitCode must be an integer from 0 through 4.")
    if is_v2:
        try:
            expected_exit_code = int(derive_audit_exit_code(audit))
        except AuditIntegrityError as error:
            raise PostRunAssessmentIntegrityError(
                f"Usage Rules audit evidence is invalid: {error}"
            ) from error
        if exit_code != expected_exit_code:
            raise PostRunAssessmentIntegrityError(
                "Run manifest exitCode differs from complete v2 audit evidence."
            )
    if not isinstance(manifest.get("productionReady"), bool) or not isinstance(
        audit.get("productionReady"), bool
    ):
        raise PostRunAssessmentIntegrityError("Final evidence productionReady fields must be boolean.")
    if manifest["productionReady"] != audit["productionReady"]:
        raise PostRunAssessmentIntegrityError("Final evidence productionReady values differ.")

    design = _object(audit.get("designSystemLane"), "designSystemLane")
    ux = _object(audit.get("uxAccessibilityLane"), "uxAccessibilityLane")
    coverage = _object(audit.get("coverage"), "coverage")
    enforcement = _object(audit.get("enforcementAuthorityLane"), "enforcementAuthorityLane")
    project = _object(audit.get("projectEvidence"), "projectEvidence")
    usage = (
        _object(audit.get("usageRulesLane"), "usageRulesLane")
        if is_v2
        else None
    )
    design_status = _status(design.get("status"), _DESIGN_STATUSES, "designSystemLane")
    ux_status = _status(ux.get("status"), _UX_STATUSES, "uxAccessibilityLane")
    coverage_status = _status(coverage.get("status"), _COVERAGE_STATUSES, "coverage")
    enforcement_status = _status(
        enforcement.get("status"), _ENFORCEMENT_STATUSES, "enforcementAuthorityLane"
    )
    analysis_attestation_digest = _digest(
        audit.get("analysisAttestationDigest"), "analysisAttestationDigest"
    )
    source_cut_digest = _digest(design.get("sourceCutDigest"), "sourceCutDigest")
    assessed_tree_digest = _digest(project.get("assessedTreeDigest"), "assessedTreeDigest")
    analysis_inputs_digest = _digest(project.get("analysisInputsDigest"), "analysisInputsDigest")

    usage_status = None
    usage_lane_digest = None
    active_usage_rules: list[str] = []
    assessed_usage_rules: list[str] = []
    violated_usage_rules: list[str] = []
    informative_usage_rules: list[str] = []
    unassessed_usage_rules: list[dict[str, str]] = []
    if usage is not None:
        usage_status = _status(
            usage.get("status"), _USAGE_STATUSES, "usageRulesLane"
        )
        usage_lane_digest = sha256_digest(usage)
        if manifest.get("usageRulesLaneDigest") != usage_lane_digest:
            raise PostRunAssessmentIntegrityError(
                "Run manifest Usage Rules lane digest differs from the audit."
            )
        for field, target in (
            ("activeRuleIds", active_usage_rules),
            ("assessedRuleIds", assessed_usage_rules),
            ("violatedRuleIds", violated_usage_rules),
            ("informativeRuleIds", informative_usage_rules),
        ):
            value = usage.get(field)
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise PostRunAssessmentIntegrityError(
                    f"usageRulesLane.{field} must be an array of rule IDs."
                )
            target.extend(value)
        raw_not_assessed = usage.get("notAssessed")
        if not isinstance(raw_not_assessed, list) or not all(
            isinstance(item, dict) for item in raw_not_assessed
        ):
            raise PostRunAssessmentIntegrityError(
                "usageRulesLane.notAssessed must be an array of objects."
            )
        unassessed_usage_rules = copy.deepcopy(raw_not_assessed)

    violations = design.get("violations")
    gaps = design.get("gaps")
    ux_checks = ux.get("checks")
    if not isinstance(violations, list) or not all(isinstance(item, dict) for item in violations):
        raise PostRunAssessmentIntegrityError("designSystemLane violations must be an array of objects.")
    if not isinstance(gaps, list) or not all(isinstance(item, dict) for item in gaps):
        raise PostRunAssessmentIntegrityError("designSystemLane gaps must be an array of objects.")
    if not isinstance(ux_checks, list) or not all(isinstance(item, dict) for item in ux_checks):
        raise PostRunAssessmentIntegrityError("uxAccessibilityLane checks must be an array of objects.")
    sentinel_count = _nonnegative_integer(design.get("sentinelCount"), "sentinelCount")
    resolution_summary = _object(design.get("resolutionSummary"), "resolutionSummary")
    if set(resolution_summary) != set(_RESOLUTION_STATUSES):
        raise PostRunAssessmentIntegrityError("resolutionSummary must contain every exact status count.")
    resolution_counts = {
        status: _nonnegative_integer(resolution_summary[status], f"resolutionSummary.{status}")
        for status in _RESOLUTION_STATUSES
    }
    ux_statuses = [
        _status(item.get("status"), {"allowed", "gap", "not_assessed"}, "UX check")
        for item in ux_checks
    ]

    reasons: dict[tuple[str, str], int] = {}

    def add_reason(reason_code: str, attribution: str, count: int) -> None:
        if attribution not in ALLOWED_ATTRIBUTIONS:
            raise PostRunAssessmentIntegrityError("Post-run attribution is outside the fixed contract.")
        if count > 0:
            key = (reason_code, attribution)
            reasons[key] = reasons.get(key, 0) + count

    add_reason("design_system_violation", "project_implementation", len(violations))
    add_reason("design_system_gap", "design_system", len(gaps))
    add_reason("design_system_identity_missing", "design_system", sentinel_count)
    for resolution_status, (reason_code, attribution) in _RESOLUTION_REASONS.items():
        add_reason(reason_code, attribution, resolution_counts[resolution_status])
    if design_status in {"stale", "source_unavailable", "source_incomplete"}:
        add_reason(f"design_system_{design_status}", "source", 1)
    elif design_status == "unsupported":
        add_reason("design_system_unsupported", "capability_candidate", 1)
    elif design_status == "not_assessed":
        add_reason("design_system_not_assessed", "project_configuration", 1)
    elif design_status == "invalid" and not violations and resolution_counts["invalid"] == 0:
        add_reason("design_system_invalid", "project_implementation", 1)
    elif design_status == "conflict" and resolution_counts["conflict"] == 0:
        add_reason("design_system_conflict", "project_configuration", 1)
    if coverage_status == "unsupported":
        add_reason("unsupported_adapter", "capability_candidate", 1)
    elif coverage_status == "not_assessed":
        add_reason("incomplete_coverage", "project_configuration", 1)
    if ux_status == "conflict":
        add_reason("ux_conflict", "project_implementation", 1)
    elif ux_status == "not_assessed":
        add_reason("ux_not_assessed", "capability_candidate", 1)
    if enforcement_status == "not_assessed":
        add_reason("enforcement_not_assessed", "capability_candidate", 1)
    if usage_status is not None:
        add_reason(
            "usage_rule_violation",
            "project_implementation",
            len(violated_usage_rules),
        )
        add_reason(
            "usage_rule_not_assessed",
            "project_configuration",
            len(unassessed_usage_rules),
        )
        if usage_status == "unsupported":
            add_reason("usage_rules_unsupported", "capability_candidate", 1)
        elif usage_status == "invalid":
            add_reason("usage_rules_invalid", "project_implementation", 1)
        elif usage_status in {"stale", "source_unavailable", "source_incomplete"}:
            add_reason("usage_rules_source_blocked", "source", 1)

    reason_codes = [
        {"reasonCode": reason_code, "attribution": attribution, "count": count}
        for (reason_code, attribution), count in sorted(reasons.items())
    ]
    review_recommended = any(
        item["attribution"] in {"capability_candidate", "plugin_candidate"}
        for item in reason_codes
    )
    evidence_digests = {
        "runManifest": manifest_digest,
        "analysisAttestation": analysis_attestation_digest,
        "sourceCut": source_cut_digest,
        "assessedTree": assessed_tree_digest,
        "analysisInputs": analysis_inputs_digest,
    }
    statuses = {
        "run": _RUN_STATUSES[exit_code],
        "designSystem": design_status,
        "uxAccessibility": ux_status,
        "coverage": coverage_status,
        "enforcementAuthority": enforcement_status,
    }
    counts = {
        "violations": len(violations),
        "designSystemGaps": len(gaps),
        "sentinels": sentinel_count,
        "allowedResolutions": resolution_counts["allowed"],
        "nonAllowedResolutions": sum(
            count for status, count in resolution_counts.items() if status != "allowed"
        ),
        "assessedUxChecks": sum(status != "not_assessed" for status in ux_statuses),
        "unassessedUxChecks": sum(status == "not_assessed" for status in ux_statuses),
    }
    assessment = {
        "schemaVersion": schema_version,
        "runId": audit["runId"],
        "profileId": audit["profileId"],
        "snapshotId": snapshot_id,
        "policyDigest": policy_digest,
        "runtimeVersion": runtime_version,
        "evidenceDigests": evidence_digests,
        "statuses": statuses,
        "counts": counts,
        "reasonCodes": reason_codes,
        "evolutionHandoff": {
            "status": "permission_required",
            "target": "plugin-evolution-manager",
            "reviewRecommended": review_recommended,
        },
        "sourceMutationPerformed": False,
    }
    if usage is not None:
        evidence_digests["usageRulesLane"] = usage_lane_digest
        statuses["usageRules"] = usage_status
        counts.update(
            {
                "activeUsageRules": len(active_usage_rules),
                "assessedUsageRules": len(assessed_usage_rules),
                "violatedUsageRules": len(violated_usage_rules),
                "unassessedUsageRules": len(unassessed_usage_rules),
                "informativeUsageRules": len(informative_usage_rules),
            }
        )
        assessment["usageRules"] = {
            "evaluatorId": usage["evaluatorId"],
            "evaluatorContractDigest": usage["evaluatorContractDigest"],
            "authorizationDigest": usage["authorizationDigest"],
            "ruleSnapshotId": usage["ruleSnapshotId"],
            "rulesDigest": usage["rulesDigest"],
            "activeRuleIds": copy.deepcopy(active_usage_rules),
            "assessedRuleIds": copy.deepcopy(assessed_usage_rules),
            "violatedRuleIds": copy.deepcopy(violated_usage_rules),
            "informativeRuleIds": copy.deepcopy(informative_usage_rules),
            "notAssessed": copy.deepcopy(unassessed_usage_rules),
        }
    return assessment

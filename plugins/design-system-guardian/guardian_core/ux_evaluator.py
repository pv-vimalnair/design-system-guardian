"""Deterministic UX/accessibility evidence evaluation.

This module evaluates host-collected observations; callers may select a target
and provide raw evidence, but they cannot declare a status.  The returned
payload is suitable as input to Guardian's sealed audit pipeline, but it never
confers production authority by itself.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest
from .contracts import ExitCode


REQUIRED_SCREEN_AREAS = (
    "accessible_label",
    "contrast",
    "focus_order",
    "hierarchy",
    "interaction_states",
    "motion",
    "readability",
    "semantics",
    "touch_target",
)

REQUIRED_FLOW_AREAS = (
    "error_recovery",
    "focus_continuity",
    "navigation",
    "state_coverage",
)

UX_REASON_CODES = frozenset(
    {
        "ux_flow_gap",
        "ux_flow_not_assessed",
        "ux_screen_gap",
        "ux_screen_not_assessed",
    }
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CHECK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OBSERVATION_KEYS = {
    "checkId",
    "targetDigest",
    "area",
    "operator",
    "observed",
    "expected",
    "evidenceDigest",
}
_OPERATORS = {"at_least", "at_most", "contains_all", "equals", "non_empty"}
_RESULT_KEYS = {
    "schemaVersion",
    "scope",
    "status",
    "complete",
    "evaluatorDigest",
    "sourceCutDigest",
    "targetDigest",
    "checks",
    "reasonCodes",
    "canAuthorizeProduction",
}
_CHECK_KEYS = {
    "checkId",
    "targetScope",
    "targetDigest",
    "area",
    "status",
    "reasonCode",
    "evidenceDigest",
}


def _contract_payload() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "algorithmVersion": 1,
        "name": "design-system-guardian-ux-evaluator",
        "requiredScreenAreas": list(REQUIRED_SCREEN_AREAS),
        "requiredFlowAreas": list(REQUIRED_FLOW_AREAS),
        "operators": sorted(_OPERATORS),
        "reasonCodes": sorted(UX_REASON_CODES),
        "statuses": ["allowed", "conflict", "not_assessed"],
        "canAuthorizeProduction": False,
    }


UX_EVALUATOR_CONTRACT_DIGEST = sha256_digest(_contract_payload())


class UxEvaluationIntegrityError(ValueError):
    """Raised when UX evidence is ambiguous, unbound, or caller-authoritative."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise UxEvaluationIntegrityError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _canonical_digest(value: Any, field: str) -> str:
    try:
        return sha256_digest(value)
    except (TypeError, ValueError) as error:
        raise UxEvaluationIntegrityError(f"{field} must contain canonical JSON evidence.") from error


def _number(value: Any, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UxEvaluationIntegrityError(f"{field} must be a finite number.")
    if not math.isfinite(value):
        raise UxEvaluationIntegrityError(f"{field} must be a finite number.")
    return value


def _compare(operator: str, observed: Any, expected: Any) -> bool:
    try:
        canonical_json_bytes(observed)
        canonical_json_bytes(expected)
        if operator == "equals":
            return canonical_json_bytes(observed) == canonical_json_bytes(expected)
        if operator == "at_least":
            return _number(observed, "observed") >= _number(expected, "expected")
        if operator == "at_most":
            return _number(observed, "observed") <= _number(expected, "expected")
        if operator == "contains_all":
            if (
                isinstance(observed, (str, bytes))
                or isinstance(expected, (str, bytes))
                or not isinstance(observed, Sequence)
                or not isinstance(expected, Sequence)
            ):
                raise UxEvaluationIntegrityError(
                    "contains_all requires observed and expected arrays."
                )
            observed_items = {canonical_json_bytes(item) for item in observed}
            return all(canonical_json_bytes(item) in observed_items for item in expected)
        if operator == "non_empty":
            if expected is not None:
                raise UxEvaluationIntegrityError("non_empty requires expected to be null.")
            if isinstance(observed, (str, bytes, Sequence, Mapping)):
                return len(observed) > 0
            raise UxEvaluationIntegrityError(
                "non_empty requires a string, array, or object observation."
            )
    except (TypeError, ValueError) as error:
        if isinstance(error, UxEvaluationIntegrityError):
            raise
        raise UxEvaluationIntegrityError(
            "UX observed and expected values must be canonical JSON evidence."
        ) from error
    raise UxEvaluationIntegrityError(f"Unsupported UX comparison operator: {operator!r}.")


def _screen_target(target: Any) -> tuple[dict[str, Any], list[str], str]:
    if not isinstance(target, Mapping) or set(target) != {"screenDigest"}:
        raise UxEvaluationIntegrityError(
            "Screen checkpoint target has unknown or missing fields."
        )
    screen_digest = _digest(target.get("screenDigest"), "screenDigest")
    normalized = {"screenDigest": screen_digest}
    return normalized, [screen_digest], ""


def _flow_target(target: Any) -> tuple[dict[str, Any], list[str], str]:
    if not isinstance(target, Mapping) or set(target) != {"flowDigest", "screenDigests"}:
        raise UxEvaluationIntegrityError("Final-flow target has unknown or missing fields.")
    flow_digest = _digest(target.get("flowDigest"), "flowDigest")
    screen_digests = target.get("screenDigests")
    if (
        isinstance(screen_digests, (str, bytes))
        or not isinstance(screen_digests, Sequence)
        or not screen_digests
    ):
        raise UxEvaluationIntegrityError(
            "Final-flow target requires at least one screen digest."
        )
    normalized_screens = [
        _digest(item, f"screenDigests[{index}]")
        for index, item in enumerate(screen_digests)
    ]
    if len(normalized_screens) != len(set(normalized_screens)):
        raise UxEvaluationIntegrityError("Final-flow screen digests must be unique.")
    if flow_digest in normalized_screens:
        raise UxEvaluationIntegrityError("Flow and screen digests must identify different targets.")
    normalized = {"flowDigest": flow_digest, "screenDigests": normalized_screens}
    return normalized, normalized_screens, flow_digest


def _normalize_observations(
    observations: Any,
    *,
    screen_digests: Sequence[str],
    flow_digest: str,
) -> list[dict[str, Any]]:
    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise UxEvaluationIntegrityError("UX observations must be an array.")

    screens = set(screen_digests)
    known_targets = screens | ({flow_digest} if flow_digest else set())
    normalized: list[dict[str, Any]] = []
    check_ids: set[str] = set()
    covered_areas: set[tuple[str, str]] = set()
    for item in observations:
        if not isinstance(item, Mapping) or set(item) != _OBSERVATION_KEYS:
            raise UxEvaluationIntegrityError(
                "UX observation has unknown or missing fields; callers cannot supply status."
            )
        check_id = item.get("checkId")
        if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
            raise UxEvaluationIntegrityError("UX checkId must be one exact safe identifier.")
        if check_id in check_ids:
            raise UxEvaluationIntegrityError("UX observation checkId values must be unique.")
        check_ids.add(check_id)

        target_digest = _digest(item.get("targetDigest"), "targetDigest")
        if target_digest not in known_targets:
            raise UxEvaluationIntegrityError(
                "UX observation target is outside the selected target."
            )
        area = item.get("area")
        expected_areas = REQUIRED_SCREEN_AREAS if target_digest in screens else REQUIRED_FLOW_AREAS
        if area not in expected_areas:
            raise UxEvaluationIntegrityError(
                "UX observation area does not belong to its screen or flow target."
            )
        coverage_key = (target_digest, str(area))
        if coverage_key in covered_areas:
            raise UxEvaluationIntegrityError(
                "UX observations must contain one exact check per target area."
            )
        covered_areas.add(coverage_key)
        operator = item.get("operator")
        if operator not in _OPERATORS:
            raise UxEvaluationIntegrityError("UX observation operator is unsupported.")
        evidence_digest = _digest(item.get("evidenceDigest"), "evidenceDigest")
        passed = _compare(str(operator), item.get("observed"), item.get("expected"))
        reason_code = None if passed else (
            "ux_screen_gap" if target_digest in screens else "ux_flow_gap"
        )
        normalized.append(
            {
                "checkId": check_id,
                "targetScope": "screen" if target_digest in screens else "flow",
                "targetDigest": target_digest,
                "area": area,
                "status": "allowed" if passed else "gap",
                "reasonCode": reason_code,
                "evidenceDigest": evidence_digest,
            }
        )
    return normalized


def _missing_checks(
    checks: Sequence[Mapping[str, Any]],
    *,
    screen_digests: Sequence[str],
    flow_digest: str,
) -> list[dict[str, Any]]:
    covered = {(item["targetDigest"], item["area"]) for item in checks}
    missing: list[dict[str, Any]] = []
    required_targets = [
        *(('screen', digest, REQUIRED_SCREEN_AREAS) for digest in screen_digests),
        *((('flow', flow_digest, REQUIRED_FLOW_AREAS),) if flow_digest else ()),
    ]
    for target_kind, target_digest, areas in required_targets:
        reason_code = (
            "ux_screen_not_assessed" if target_kind == "screen" else "ux_flow_not_assessed"
        )
        for area in areas:
            if (target_digest, area) in covered:
                continue
            missing.append(
                {
                    "checkId": f"guardian-ux-missing-{target_kind}-{target_digest[:12]}-{area}",
                    "targetScope": target_kind,
                    "targetDigest": target_digest,
                    "area": area,
                    "status": "not_assessed",
                    "reasonCode": reason_code,
                    "evidenceDigest": None,
                }
            )
    return missing


def _evaluate(
    *,
    scope: str,
    target: Any,
    observations: Any,
    source_cut: Any,
) -> dict[str, Any]:
    if not isinstance(source_cut, Mapping) or not source_cut:
        raise UxEvaluationIntegrityError("sourceCut must be one non-empty object.")
    source_cut_digest = _canonical_digest(source_cut, "sourceCut")

    if scope == "screen_checkpoint":
        normalized_target, screen_digests, flow_digest = _screen_target(target)
    elif scope == "final_flow":
        normalized_target, screen_digests, flow_digest = _flow_target(target)
    else:
        raise UxEvaluationIntegrityError("UX evaluation scope is unsupported.")

    checks = _normalize_observations(
        observations,
        screen_digests=screen_digests,
        flow_digest=flow_digest,
    )
    checks.extend(
        _missing_checks(
            checks,
            screen_digests=screen_digests,
            flow_digest=flow_digest,
        )
    )
    checks.sort(
        key=lambda item: (
            item["targetDigest"],
            item["area"],
            item["checkId"],
        )
    )

    reason_counts = Counter(
        item["reasonCode"] for item in checks if item["reasonCode"] is not None
    )
    has_not_assessed = any(item["status"] == "not_assessed" for item in checks)
    has_gap = any(item["status"] == "gap" for item in checks)
    if has_gap:
        status = "conflict"
    elif has_not_assessed:
        status = "not_assessed"
    else:
        status = "allowed"

    return {
        "schemaVersion": 1,
        "scope": scope,
        "status": status,
        "complete": not has_not_assessed,
        "evaluatorDigest": UX_EVALUATOR_CONTRACT_DIGEST,
        "sourceCutDigest": source_cut_digest,
        "targetDigest": _canonical_digest(normalized_target, "target"),
        "checks": checks,
        "reasonCodes": [
            {"reasonCode": reason_code, "count": reason_counts[reason_code]}
            for reason_code in sorted(reason_counts)
        ],
        # Phase-local UX evidence is never a production authority. Only the
        # protected Guardian finalizer may derive productionReady.
        "canAuthorizeProduction": False,
    }


def audit_checks_from_evaluation(
    result: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    source_cut: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Validate one evaluator result and project fixed audit-lane check objects.

    Structural validation is not a production attestation. The host must still
    seal the evaluator result with the task's trusted analysis evidence.
    """

    if not isinstance(result, Mapping) or set(result) != _RESULT_KEYS:
        raise UxEvaluationIntegrityError(
            "UX evaluation result has unknown or missing fields."
        )
    try:
        canonical_json_bytes(result)
    except (TypeError, ValueError) as error:
        raise UxEvaluationIntegrityError(
            "UX evaluation result must be canonical JSON evidence."
        ) from error
    if result.get("schemaVersion") != 1:
        raise UxEvaluationIntegrityError("UX evaluation schemaVersion must be exactly 1.")
    scope = result.get("scope")
    if scope == "screen_checkpoint":
        normalized_target, expected_screens, expected_flow = _screen_target(target)
    elif scope == "final_flow":
        normalized_target, expected_screens, expected_flow = _flow_target(target)
    else:
        raise UxEvaluationIntegrityError("UX evaluation scope is unsupported.")
    if result.get("targetDigest") != _canonical_digest(normalized_target, "target"):
        raise UxEvaluationIntegrityError(
            "UX evaluation is not bound to the selected target."
        )
    if result.get("evaluatorDigest") != UX_EVALUATOR_CONTRACT_DIGEST:
        raise UxEvaluationIntegrityError(
            "UX evaluation is not bound to the built-in evaluator contract."
        )
    if not isinstance(source_cut, Mapping) or not source_cut:
        raise UxEvaluationIntegrityError("sourceCut must be one non-empty object.")
    expected_source_cut_digest = _canonical_digest(source_cut, "sourceCut")
    if result.get("sourceCutDigest") != expected_source_cut_digest:
        raise UxEvaluationIntegrityError(
            "UX evaluation is not bound to the pinned source cut."
        )
    if result.get("canAuthorizeProduction") is not False:
        raise UxEvaluationIntegrityError(
            "Phase-local UX evidence cannot authorize production."
        )

    checks = result.get("checks")
    if not isinstance(checks, list):
        raise UxEvaluationIntegrityError("UX evaluation checks must be an array.")
    normalized: list[dict[str, Any]] = []
    check_ids: set[str] = set()
    covered_areas: set[tuple[str, str]] = set()
    targets_by_scope: dict[str, set[str]] = {"screen": set(), "flow": set()}
    reason_counts: Counter[str] = Counter()
    for item in checks:
        if not isinstance(item, Mapping) or set(item) != _CHECK_KEYS:
            raise UxEvaluationIntegrityError(
                "UX evaluation check has unknown or missing fields."
            )
        check_id = item.get("checkId")
        if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
            raise UxEvaluationIntegrityError("UX checkId must be one exact safe identifier.")
        if check_id in check_ids:
            raise UxEvaluationIntegrityError("UX evaluation checkId values must be unique.")
        check_ids.add(check_id)
        target_scope = item.get("targetScope")
        if target_scope not in {"screen", "flow"}:
            raise UxEvaluationIntegrityError("UX check targetScope is invalid.")
        if scope == "screen_checkpoint" and target_scope != "screen":
            raise UxEvaluationIntegrityError(
                "A screen checkpoint cannot contain final-flow checks."
            )
        area = item.get("area")
        required_areas = (
            REQUIRED_SCREEN_AREAS if target_scope == "screen" else REQUIRED_FLOW_AREAS
        )
        if area not in required_areas:
            raise UxEvaluationIntegrityError("UX check area is outside its target scope.")
        target_digest = _digest(item.get("targetDigest"), "targetDigest")
        coverage_key = (target_digest, str(area))
        if coverage_key in covered_areas:
            raise UxEvaluationIntegrityError(
                "UX evaluation must contain one exact check per target area."
            )
        covered_areas.add(coverage_key)
        targets_by_scope[target_scope].add(target_digest)
        status = item.get("status")
        reason_code = item.get("reasonCode")
        evidence_digest = item.get("evidenceDigest")
        prefix = f"ux_{target_scope}"
        if status == "allowed":
            if reason_code is not None:
                raise UxEvaluationIntegrityError("Allowed UX check cannot carry a reason code.")
            evidence_digest = _digest(evidence_digest, "evidenceDigest")
            message = "UX/accessibility evidence satisfied the required check."
        elif status == "gap":
            if reason_code != f"{prefix}_gap":
                raise UxEvaluationIntegrityError("UX gap has the wrong fixed reason code.")
            evidence_digest = _digest(evidence_digest, "evidenceDigest")
            message = "UX/accessibility evidence did not satisfy the required check."
            reason_counts[reason_code] += 1
        elif status == "not_assessed":
            if reason_code != f"{prefix}_not_assessed" or evidence_digest is not None:
                raise UxEvaluationIntegrityError(
                    "Unassessed UX check has invalid evidence or reason code."
                )
            message = "Required UX/accessibility evidence was unavailable for this check."
            reason_counts[reason_code] += 1
        else:
            raise UxEvaluationIntegrityError("UX check status is unsupported.")
        normalized.append(
            {
                "checkId": check_id,
                "area": area,
                "status": status,
                "message": message,
                "evidence": {
                    "scope": target_scope,
                    "targetDigest": target_digest,
                    "evidenceDigest": evidence_digest,
                    "reasonCode": reason_code,
                    "evaluatorDigest": UX_EVALUATOR_CONTRACT_DIGEST,
                    "sourceCutDigest": expected_source_cut_digest,
                },
            }
        )

    expected_flow_targets = {expected_flow} if expected_flow else set()
    if (
        targets_by_scope["screen"] != set(expected_screens)
        or targets_by_scope["flow"] != expected_flow_targets
    ):
        raise UxEvaluationIntegrityError(
            "UX evaluation target coverage differs from the selected target."
        )
    for target_scope, target_digests in targets_by_scope.items():
        required_areas = (
            set(REQUIRED_SCREEN_AREAS)
            if target_scope == "screen"
            else set(REQUIRED_FLOW_AREAS)
        )
        for target_digest in target_digests:
            actual_areas = {
                area for digest, area in covered_areas if digest == target_digest
            }
            if actual_areas != required_areas:
                raise UxEvaluationIntegrityError(
                    "UX evaluation target does not have complete required-area coverage."
                )

    expected_reasons = [
        {"reasonCode": reason_code, "count": reason_counts[reason_code]}
        for reason_code in sorted(reason_counts)
    ]
    if result.get("reasonCodes") != expected_reasons:
        raise UxEvaluationIntegrityError(
            "UX evaluation reason-code summary differs from its checks."
        )
    has_not_assessed = any(item["status"] == "not_assessed" for item in normalized)
    if any(item["status"] == "gap" for item in normalized):
        expected_status = "conflict"
    elif has_not_assessed:
        expected_status = "not_assessed"
    else:
        expected_status = "allowed"
    if result.get("status") != expected_status:
        raise UxEvaluationIntegrityError(
            "UX evaluation status differs from its exact checks."
        )
    if result.get("complete") is not (not has_not_assessed):
        raise UxEvaluationIntegrityError(
            "UX evaluation completeness differs from its exact checks."
        )
    # This portable build has no protected UX observation provider. Preserve
    # proven gaps, but never promote caller-carried positive claims to a pass.
    for item in normalized:
        if item["status"] != "allowed":
            continue
        scope = item["evidence"]["scope"]
        item["status"] = "not_assessed"
        item["message"] = "Required UX/accessibility evidence was unavailable for this check."
        item["evidence"]["evidenceDigest"] = None
        item["evidence"]["reasonCode"] = f"ux_{scope}_not_assessed"
    return sorted(normalized, key=canonical_json_bytes)


def evaluate_screen_checkpoint(
    *,
    target: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    source_cut: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate one completed screen as a non-authoritative quick checkpoint."""

    return _evaluate(
        scope="screen_checkpoint",
        target=target,
        observations=observations,
        source_cut=source_cut,
    )


def evaluate_final_flow(
    *,
    target: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    source_cut: Mapping[str, Any],
) -> dict[str, Any]:
    """Re-evaluate every selected screen plus the complete flow for final audit input."""

    return _evaluate(
        scope="final_flow",
        target=target,
        observations=observations,
        source_cut=source_cut,
    )


__all__ = [
    "REQUIRED_FLOW_AREAS",
    "REQUIRED_SCREEN_AREAS",
    "UX_EVALUATOR_CONTRACT_DIGEST",
    "UX_REASON_CODES",
    "UxEvaluationIntegrityError",
    "audit_checks_from_evaluation",
    "evaluate_final_flow",
    "evaluate_screen_checkpoint",
]

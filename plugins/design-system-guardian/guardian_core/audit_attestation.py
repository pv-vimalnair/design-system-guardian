"""Host-sealed binding between one trusted adapter run and one audit result."""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .adapter_dispatch import AdapterDispatchError, verify_figma_runner_evidence
from .audit import adapter_audit_projection, canonical_untrusted_ux_lane
from .canonical import sha256_digest
from .flutter_adapter import FlutterAdapterIntegrityError, normalize_flutter_adapter_result
from .flutter_runner import verify_flutter_project_evidence
from .project_binding import ProjectBindingError, project_evidence_from_runner
from .ux_evaluator import UxEvaluationIntegrityError, audit_checks_from_evaluation


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEYS_V1 = {
    "schemaVersion",
    "runId",
    "profileId",
    "snapshotId",
    "policyDigest",
    "configDigest",
    "runnerEvidenceDigest",
    "runnerEvidence",
    "auditResultDigest",
}
_KEYS_V2 = _KEYS_V1 | {
    "uxTarget",
    "uxEvaluation",
    "uxEvaluationDigest",
}


class AnalysisAttestationIntegrityError(ValueError):
    """Raised when analyzer evidence is forged, replayed, or no longer current."""


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise AnalysisAttestationIntegrityError(
            f"Analysis attestation {field} must be a lowercase SHA-256 digest."
        )
    return value


def _identity(run_pin: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(run_pin, Mapping) or run_pin.get("schemaVersion") not in {1, 2}:
        raise AnalysisAttestationIntegrityError("Analysis attestation requires a verified run pin.")
    output: dict[str, str] = {}
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        value = run_pin.get(field)
        if not isinstance(value, str) or not value:
            raise AnalysisAttestationIntegrityError(f"Run pin {field} is invalid.")
        output[field] = value
    _digest(output["snapshotId"], "snapshotId")
    _digest(output["policyDigest"], "policyDigest")
    return output


def _normalized_runner_adapter(
    runner_evidence: Mapping[str, Any],
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    adapter_config: Mapping[str, Any] | None,
    verified_snapshot: Mapping[str, Any] | None,
) -> dict[str, Any]:
    raw = runner_evidence.get("adapterResult")
    adapter = runner_evidence.get("adapter")
    if adapter is None and isinstance(raw, Mapping):
        adapter = raw.get("adapter")

    if adapter == "figma":
        if not isinstance(verified_snapshot, Mapping):
            raise AnalysisAttestationIntegrityError(
                "Figma attestation requires the verified pinned snapshot."
            )
        try:
            verified = verify_figma_runner_evidence(
                runner_evidence,
                run_pin=dict(run_pin),
                verified_snapshot=dict(verified_snapshot),
                config_digest=config_digest,
            )
        except (AdapterDispatchError, ValueError) as error:
            raise AnalysisAttestationIntegrityError(
                f"Figma runner evidence is invalid: {error}"
            ) from error
        normalized = verified.get("normalizedAdapterResult")
        if not isinstance(normalized, dict):
            raise AnalysisAttestationIntegrityError(
                "Figma runner evidence lacks its exact normalized adapter result."
            )
        return copy.deepcopy(normalized)

    if adapter == "flutter":
        if not isinstance(adapter_config, Mapping):
            raise AnalysisAttestationIntegrityError(
                "Flutter attestation requires the exact regenerated adapter config."
            )
        try:
            normalized = normalize_flutter_adapter_result(
                raw,
                adapter_config=dict(adapter_config),
                run_pin=dict(run_pin),
            )
        except (FlutterAdapterIntegrityError, ValueError) as error:
            raise AnalysisAttestationIntegrityError(
                f"Flutter runner adapter evidence is invalid: {error}"
            ) from error
        claimed = runner_evidence.get("normalizedAdapterResult")
        if claimed is not None and claimed != normalized:
            raise AnalysisAttestationIntegrityError(
                "Flutter runner normalized evidence differs from its exact analyzer result."
            )
        return normalized

    raise AnalysisAttestationIntegrityError(
        "Analysis attestation uses an unsupported adapter."
    )


def _verify_audit_projection(
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    normalized_adapter_result: Mapping[str, Any],
    audit_result: Mapping[str, Any],
) -> None:
    try:
        coverage, diagnostics = adapter_audit_projection(
            dict(normalized_adapter_result),
            dict(run_pin["sourceCut"]),
            run_pin=dict(run_pin),
        )
    except (ValueError, KeyError) as error:
        raise AnalysisAttestationIntegrityError(
            f"Normalized adapter evidence cannot be projected into the audit: {error}"
        ) from error
    if coverage.get("configDigest") != config_digest:
        raise AnalysisAttestationIntegrityError(
            "Normalized adapter evidence differs from the exact adapter config."
        )
    if audit_result.get("coverage") != coverage:
        raise AnalysisAttestationIntegrityError(
            "Audit coverage differs from the exact normalized adapter evidence."
        )
    design_lane = audit_result.get("designSystemLane")
    if not isinstance(design_lane, Mapping):
        raise AnalysisAttestationIntegrityError(
            "Audit result lacks its design-system evidence lane."
        )
    expected_violations = [item for item in diagnostics if item["kind"] == "violation"]
    expected_gaps = [item for item in diagnostics if item["kind"] == "design_system_gap"]
    if (
        design_lane.get("violations") != expected_violations
        or design_lane.get("gaps") != expected_gaps
    ):
        raise AnalysisAttestationIntegrityError(
            "Audit diagnostics differ from the exact normalized adapter evidence."
        )


def build_analysis_attestation(
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    runner_evidence: Mapping[str, Any],
    audit_result: Mapping[str, Any],
    ux_target: Mapping[str, Any] | None = None,
    ux_evaluation: Mapping[str, Any] | None = None,
    adapter_config: Mapping[str, Any] | None = None,
    verified_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the exact payload that the host authority must seal after audit."""

    identity = _identity(run_pin)
    config_digest = _digest(config_digest, "configDigest")
    if not isinstance(runner_evidence, Mapping) or not isinstance(audit_result, Mapping):
        raise AnalysisAttestationIntegrityError("Runner evidence and audit result must be objects.")
    normalized_adapter_result = _normalized_runner_adapter(
        runner_evidence,
        run_pin=run_pin,
        config_digest=config_digest,
        adapter_config=adapter_config,
        verified_snapshot=verified_snapshot,
    )
    _verify_audit_projection(
        run_pin=run_pin,
        config_digest=config_digest,
        normalized_adapter_result=normalized_adapter_result,
        audit_result=audit_result,
    )
    binding = runner_evidence.get("adapterResult", {}).get("binding")
    if not isinstance(binding, Mapping):
        raise AnalysisAttestationIntegrityError("Runner evidence lacks an adapter binding.")
    expected_binding = {
        "profileId": identity["profileId"],
        "snapshotId": identity["snapshotId"],
        "policyDigest": identity["policyDigest"],
        "configDigest": config_digest,
    }
    for field, expected in expected_binding.items():
        if binding.get(field) != expected:
            raise AnalysisAttestationIntegrityError(
                f"Runner evidence {field} differs from the verified run."
            )
    runner_digest = sha256_digest(runner_evidence)
    try:
        expected_project = project_evidence_from_runner(
            run_pin.get("projectBinding"), runner_evidence.get("project")
        )
    except ProjectBindingError as error:
        raise AnalysisAttestationIntegrityError(
            f"Runner project evidence is invalid: {error}"
        ) from error
    if audit_result.get("projectEvidence") != expected_project:
        raise AnalysisAttestationIntegrityError("Audit result targets a different project.")
    if audit_result.get("analysisAttestationDigest") != runner_digest:
        raise AnalysisAttestationIntegrityError(
            "Audit result is not bound to the exact trusted runner evidence."
        )
    for field, expected in identity.items():
        if audit_result.get(field) != expected:
            raise AnalysisAttestationIntegrityError(
                f"Audit result {field} differs from the verified run."
            )
    base = {
        **identity,
        "configDigest": config_digest,
        "runnerEvidenceDigest": runner_digest,
        "runnerEvidence": copy.deepcopy(dict(runner_evidence)),
        "auditResultDigest": sha256_digest(audit_result),
    }
    if ux_target is None and ux_evaluation is None:
        if audit_result.get("uxAccessibilityLane") != canonical_untrusted_ux_lane():
            raise AnalysisAttestationIntegrityError(
                "An attestation without UX evidence requires the canonical untrusted UX lane."
            )
        return {"schemaVersion": 1, **base}
    if not isinstance(ux_target, Mapping) or not isinstance(ux_evaluation, Mapping):
        raise AnalysisAttestationIntegrityError(
            "Trusted UX attestation requires both target and evaluation evidence."
        )
    if ux_evaluation.get("scope") != "final_flow":
        raise AnalysisAttestationIntegrityError(
            "Only a complete final-flow UX evaluation may enter final audit evidence."
        )
    source_cut = run_pin.get("sourceCut")
    if not isinstance(source_cut, Mapping):
        raise AnalysisAttestationIntegrityError("Run pin source cut is invalid.")
    try:
        expected_checks = audit_checks_from_evaluation(
            ux_evaluation,
            target=ux_target,
            source_cut=source_cut,
        )
    except UxEvaluationIntegrityError as error:
        raise AnalysisAttestationIntegrityError(
            f"Trusted UX evaluation is invalid: {error}"
        ) from error
    ux_lane = audit_result.get("uxAccessibilityLane")
    if not isinstance(ux_lane, Mapping) or ux_lane.get("checks") != expected_checks:
        raise AnalysisAttestationIntegrityError(
            "Audit UX checks differ from the exact built-in evaluator result."
        )
    return {
        "schemaVersion": 1,
        **base,
        "uxTarget": copy.deepcopy(dict(ux_target)),
        "uxEvaluation": copy.deepcopy(dict(ux_evaluation)),
        "uxEvaluationDigest": sha256_digest(ux_evaluation),
    }


def verify_analysis_attestation(
    payload: Any,
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    audit_result: Mapping[str, Any],
    verified_snapshot: Mapping[str, Any] | None = None,
    adapter_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Rebuild the sealed payload and prove its product manifest is still current."""

    if not isinstance(payload, dict):
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation must be an object."
        )
    if payload.get("schemaVersion") != 1:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation schemaVersion must be exactly 1."
        )
    has_ux_evaluation = set(payload) == _KEYS_V2
    if not has_ux_evaluation and set(payload) != _KEYS_V1:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation has unknown or missing fields."
        )
    expected = build_analysis_attestation(
        run_pin=run_pin,
        config_digest=config_digest,
        runner_evidence=payload.get("runnerEvidence"),
        audit_result=audit_result,
        ux_target=payload.get("uxTarget") if has_ux_evaluation else None,
        ux_evaluation=payload.get("uxEvaluation") if has_ux_evaluation else None,
        adapter_config=adapter_config,
        verified_snapshot=verified_snapshot,
    )
    if payload != expected:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation differs from the exact host-derived evidence."
        )
    runner = payload["runnerEvidence"]
    adapter_result = runner.get("adapterResult") if isinstance(runner, Mapping) else None
    adapter = adapter_result.get("adapter") if isinstance(adapter_result, Mapping) else None
    if adapter == "flutter" or (not has_ux_evaluation and adapter is None):
        verify_flutter_project_evidence(runner)
    elif adapter == "figma":
        if not isinstance(verified_snapshot, dict):
            raise AnalysisAttestationIntegrityError(
                "Figma attestation requires the verified pinned snapshot."
            )
        try:
            verify_figma_runner_evidence(
                runner,
                run_pin=dict(run_pin),
                verified_snapshot=dict(verified_snapshot),
                config_digest=config_digest,
            )
        except (AdapterDispatchError, ValueError) as error:
            raise AnalysisAttestationIntegrityError(
                f"Figma runner evidence is invalid: {error}"
            ) from error
    else:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation uses an unsupported adapter."
        )
    return copy.deepcopy(payload)


__all__ = [
    "AnalysisAttestationIntegrityError",
    "build_analysis_attestation",
    "verify_analysis_attestation",
]

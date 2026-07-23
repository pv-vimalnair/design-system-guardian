"""Host-sealed binding between one trusted adapter run and one audit result."""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .canonical import sha256_digest
from .flutter_runner import verify_flutter_project_evidence
from .project_binding import ProjectBindingError, project_evidence_from_runner


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEYS = {
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


class AnalysisAttestationIntegrityError(ValueError):
    """Raised when analyzer evidence is forged, replayed, or no longer current."""


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise AnalysisAttestationIntegrityError(
            f"Analysis attestation {field} must be a lowercase SHA-256 digest."
        )
    return value


def _identity(run_pin: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(run_pin, Mapping) or run_pin.get("schemaVersion") != 1:
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


def build_analysis_attestation(
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    runner_evidence: Mapping[str, Any],
    audit_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Create the exact payload that the host authority must seal after audit."""

    identity = _identity(run_pin)
    config_digest = _digest(config_digest, "configDigest")
    if not isinstance(runner_evidence, Mapping) or not isinstance(audit_result, Mapping):
        raise AnalysisAttestationIntegrityError("Runner evidence and audit result must be objects.")
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
    return {
        "schemaVersion": 1,
        **identity,
        "configDigest": config_digest,
        "runnerEvidenceDigest": runner_digest,
        "runnerEvidence": copy.deepcopy(dict(runner_evidence)),
        "auditResultDigest": sha256_digest(audit_result),
    }


def verify_analysis_attestation(
    payload: Any,
    *,
    run_pin: Mapping[str, Any],
    config_digest: str,
    audit_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild the sealed payload and prove its product manifest is still current."""

    if not isinstance(payload, dict) or set(payload) != _KEYS:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation has unknown or missing fields."
        )
    expected = build_analysis_attestation(
        run_pin=run_pin,
        config_digest=config_digest,
        runner_evidence=payload.get("runnerEvidence"),
        audit_result=audit_result,
    )
    if payload != expected:
        raise AnalysisAttestationIntegrityError(
            "Analysis attestation differs from the exact host-derived evidence."
        )
    verify_flutter_project_evidence(payload["runnerEvidence"])
    return copy.deepcopy(payload)


__all__ = [
    "AnalysisAttestationIntegrityError",
    "build_analysis_attestation",
    "verify_analysis_attestation",
]

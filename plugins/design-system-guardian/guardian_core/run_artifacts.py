"""Authority-sealed run evidence and deterministic human-readable projections."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

from .audit import AUDIT_CATEGORIES, AuditIntegrityError, derive_audit_exit_code
from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import canonical_json_bytes, read_canonical_json, sha256_digest
from .enforcement_authority import (
    EnforcementAuthorityIntegrityError,
    canonicalize_enforcement_authority_lane,
)
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path
from .policy import verify_policy_anchor
from .project_binding import ProjectBindingError, validate_project_evidence
from .storage import exclusive_write_json


_ARTIFACT_TYPES = {
    "analysis-attestation",
    "audit-result",
    "coverage",
    "build-plan",
    "run-manifest",
    "post-run-assessment",
    "judgment-assessment",
}
_ENVELOPE_KEYS = {
    "schemaVersion",
    "artifactType",
    "profileId",
    "runId",
    "policyDigest",
    "payloadDigest",
    "payload",
    "authoritySeal",
}
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class RunArtifactIntegrityError(ValueError):
    """Raised when sealed run evidence or its isolated storage is invalid."""


def _validate_identity(artifact_type: Any, profile_id: Any, run_id: Any) -> tuple[str, str, str]:
    if artifact_type not in _ARTIFACT_TYPES:
        raise RunArtifactIntegrityError("Run artifact type is not part of the sealed contract.")
    if not isinstance(profile_id, str) or not profile_id:
        raise RunArtifactIntegrityError("Run artifact profileId must be a non-empty string.")
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise RunArtifactIntegrityError("Run artifact runId is not an exact safe identifier.")
    return artifact_type, profile_id, run_id


def _unsigned_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in envelope.items() if key != "authoritySeal"}


def _artifact_path(home: Path, *, profile_id: str, run_id: str, artifact_type: str) -> Path:
    _validate_identity(artifact_type, profile_id, run_id)
    path = GuardianPaths(home).audits(profile_id) / run_id / f"{artifact_type}.sealed.json"
    try:
        return assert_guardian_storage_path(home, path)
    except (PathIntegrityError, ValueError) as error:
        raise RunArtifactIntegrityError(f"Run artifact path is unsafe: {error}") from error


def _report_path(home: Path, *, profile_id: str, run_id: str) -> Path:
    _validate_identity("audit-result", profile_id, run_id)
    path = GuardianPaths(home).audits(profile_id) / run_id / "audit-report.md"
    try:
        return assert_guardian_storage_path(home, path)
    except (PathIntegrityError, ValueError) as error:
        raise RunArtifactIntegrityError(f"Readable report path is unsafe: {error}") from error


def seal_run_artifact(
    home: Path,
    *,
    artifact_type: str,
    profile_id: str,
    run_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Bind a canonical payload to one profile, run, policy, and artifact purpose."""

    normalized_home = home.expanduser().absolute()
    _validate_identity(artifact_type, profile_id, run_id)
    if not isinstance(payload, dict):
        raise RunArtifactIntegrityError("Run artifact payload must be an object.")
    if payload.get("profileId") != profile_id or payload.get("runId") != run_id:
        raise RunArtifactIntegrityError("Run artifact payload identity differs from its sealed path.")
    policy_digest = verify_policy_anchor(normalized_home)
    if payload.get("policyDigest") != policy_digest:
        raise RunArtifactIntegrityError("Run artifact payload is not bound to the immutable policy.")
    unsigned = {
        "schemaVersion": 1,
        "artifactType": artifact_type,
        "profileId": profile_id,
        "runId": run_id,
        "policyDigest": policy_digest,
        "payloadDigest": sha256_digest(payload),
        "payload": copy.deepcopy(payload),
    }
    try:
        seal = authority_seal(
            normalized_home,
            f"run-artifact:{profile_id}:{run_id}:{artifact_type}",
            unsigned,
        )
    except AuthorityIntegrityError as error:
        raise RunArtifactIntegrityError(str(error)) from error
    return {**unsigned, "authoritySeal": seal}


def verify_run_artifact(home: Path, envelope: Any) -> dict[str, Any]:
    """Return a deep copy of a payload only after all bindings and seals verify."""

    normalized_home = home.expanduser().absolute()
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
        raise RunArtifactIntegrityError("Sealed run artifact has unknown or missing fields.")
    if envelope.get("schemaVersion") != 1:
        raise RunArtifactIntegrityError("Sealed run artifact schemaVersion must be 1.")
    artifact_type, profile_id, run_id = _validate_identity(
        envelope.get("artifactType"), envelope.get("profileId"), envelope.get("runId")
    )
    policy_digest = verify_policy_anchor(normalized_home)
    if envelope.get("policyDigest") != policy_digest:
        raise RunArtifactIntegrityError("Sealed run artifact policy digest has changed.")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise RunArtifactIntegrityError("Sealed run artifact payload must be an object.")
    if payload.get("profileId") != profile_id or payload.get("runId") != run_id:
        raise RunArtifactIntegrityError("Sealed payload identity conflicts with its envelope.")
    if payload.get("policyDigest") != policy_digest:
        raise RunArtifactIntegrityError("Sealed payload policy binding is invalid.")
    claimed_digest = envelope.get("payloadDigest")
    if not isinstance(claimed_digest, str) or not _HEX_64.fullmatch(claimed_digest):
        raise RunArtifactIntegrityError("Sealed run artifact payloadDigest is malformed.")
    if sha256_digest(payload) != claimed_digest:
        raise RunArtifactIntegrityError("Sealed run artifact payload digest does not match.")
    try:
        verify_authority_seal(
            normalized_home,
            f"run-artifact:{profile_id}:{run_id}:{artifact_type}",
            _unsigned_envelope(envelope),
            envelope.get("authoritySeal"),
        )
    except AuthorityIntegrityError as error:
        raise RunArtifactIntegrityError(f"Run artifact authority seal is invalid: {error}") from error
    return copy.deepcopy(payload)


def write_run_artifact(home: Path, envelope: dict[str, Any]) -> Path:
    """Create sealed evidence once; identical retries are idempotent, conflicts fail."""

    normalized_home = home.expanduser().absolute()
    verify_run_artifact(normalized_home, envelope)
    path = _artifact_path(
        normalized_home,
        profile_id=envelope["profileId"],
        run_id=envelope["runId"],
        artifact_type=envelope["artifactType"],
    )
    try:
        exclusive_write_json(normalized_home, path, envelope)
    except FileExistsError:
        try:
            existing = read_canonical_json(path)
        except (OSError, ValueError, UnicodeError) as error:
            raise RunArtifactIntegrityError(f"Existing run artifact cannot be verified: {error}") from error
        if existing != envelope:
            raise RunArtifactIntegrityError("Append-only run evidence cannot be replaced or rewritten.")
    verify_run_artifact(normalized_home, read_canonical_json(path))
    return path


def read_run_artifact(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
    artifact_type: str,
) -> dict[str, Any]:
    """Read one canonical append-only artifact and verify its host authority seal."""

    normalized_home = home.expanduser().absolute()
    path = _artifact_path(
        normalized_home,
        profile_id=profile_id,
        run_id=run_id,
        artifact_type=artifact_type,
    )
    try:
        envelope = read_canonical_json(path)
    except (OSError, UnicodeError, ValueError) as error:
        raise RunArtifactIntegrityError(
            f"Sealed {artifact_type} artifact is missing or unreadable: {error}"
        ) from error
    verify_run_artifact(normalized_home, envelope)
    return copy.deepcopy(envelope)


def read_run_artifact_if_present(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
    artifact_type: str,
) -> dict[str, Any] | None:
    """Return verified append-only evidence, or None only when it does not exist."""

    normalized_home = home.expanduser().absolute()
    path = _artifact_path(
        normalized_home,
        profile_id=profile_id,
        run_id=run_id,
        artifact_type=artifact_type,
    )
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RunArtifactIntegrityError(
            f"Sealed {artifact_type} artifact presence cannot be verified: {error}"
        ) from error
    return read_run_artifact(
        normalized_home,
        profile_id=profile_id,
        run_id=run_id,
        artifact_type=artifact_type,
    )


def _one_line(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")


def _workspace_labels(adapter: Any) -> dict[str, str]:
    """Describe local evidence without confusing it with the assessed surface."""

    if adapter == "flutter":
        return {
            "root": "Intended project",
            "identity": "Project root identity",
            "tree": "Assessed tree",
            "inputs": "Analysis inputs",
            "commit": "Git commit (local observation)",
        }
    if adapter == "figma":
        return {
            "root": "Bound local evidence workspace",
            "identity": "Local workspace identity",
            "tree": "Assessed evidence tree",
            "inputs": "Analysis input bundle",
            "commit": "Workspace Git commit (local observation)",
        }
    return {
        "root": "Bound local workspace",
        "identity": "Local workspace identity",
        "tree": "Assessed evidence tree",
        "inputs": "Analysis inputs",
        "commit": "Workspace Git commit (local observation)",
    }


def _ux_checks_by_scope(
    checks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Partition trusted scoped checks while retaining v0.3.2 unscoped evidence."""

    screen: list[dict[str, Any]] = []
    flow: list[dict[str, Any]] = []
    legacy: list[dict[str, Any]] = []
    for item in checks:
        evidence = item.get("evidence")
        scope = evidence.get("scope") if isinstance(evidence, dict) else None
        if scope == "screen":
            screen.append(item)
        elif scope == "flow":
            flow.append(item)
        else:
            legacy.append(item)
    return screen, flow, legacy


def _next_action(
    *,
    audit: dict[str, Any],
    design_lane: dict[str, Any],
    ux_lane: dict[str, Any],
    coverage: dict[str, Any],
    authority_lane: dict[str, Any],
    usage_lane: dict[str, Any] | None,
) -> str:
    """Return one fixed, deterministic action without projecting raw evidence."""

    design_status = design_lane.get("status")
    if design_status == "invalid":
        return "Repair the invalid Guardian policy or evidence, then run the final audit again."
    if design_status in {"stale", "source_unavailable", "source_incomplete"}:
        return "Restore a fresh, complete approved catalog snapshot, then run the final audit again."

    violations = design_lane.get("violations")
    if isinstance(violations, list) and violations:
        return "Fix the reported design-system violations, then run the final audit again."
    gaps = design_lane.get("gaps")
    sentinel_count = design_lane.get("sentinelCount")
    if (isinstance(gaps, list) and gaps) or (
        isinstance(sentinel_count, int)
        and not isinstance(sentinel_count, bool)
        and sentinel_count > 0
    ):
        return (
            "Request the missing design-system assets without substituting them, "
            "then run the final audit again."
        )
    if design_status == "conflict":
        return "Resolve the reported design-system conflicts, then run the final audit again."

    if usage_lane is not None:
        usage_status = usage_lane.get("status")
        if usage_status == "invalid":
            return "Repair the invalid Usage Rules evidence, then run the final audit again."
        if usage_status in {"stale", "source_unavailable", "source_incomplete"}:
            return "Restore fresh, complete Usage Rules source evidence, then run the final audit again."
        if usage_status == "conflict":
            return "Fix the reported Usage Rules violations, then run the final audit again."
        if usage_status == "unsupported":
            return "Run Usage Rules with the pinned supported analyzer adapter."
        if usage_status == "not_assessed":
            return "Complete every gating Usage Rules assessment, then run the final audit again."

    if coverage.get("supported") is not True or coverage.get("complete") is not True:
        return "Complete supported adapter coverage, then run the final audit again."
    if design_status in {"unsupported", "not_assessed"}:
        return "Complete the design-system assessment with a supported adapter."

    ux_status = ux_lane.get("status")
    if ux_status == "conflict":
        return "Fix the reported UX/accessibility gaps, then run the final-flow evaluation again."
    if ux_status != "allowed":
        return "Complete the final screen-and-flow UX/accessibility evaluation."
    if authority_lane.get("status") != "allowed":
        return "Run the sealed result through a host with protected production authority."
    if audit.get("productionReady") is True:
        return "None; this sealed audit is production-ready."
    return "Resolve the remaining blocking lane, then run the final audit again."


def _append_checks(
    lines: list[str],
    *,
    title: str,
    checks: list[dict[str, Any]],
    empty_message: str,
) -> None:
    lines.extend(["", f"### {title}", ""])
    if not checks:
        lines.append(empty_message)
        return
    for item in checks:
        lines.append(
            f"- [{_one_line(item.get('status'))}] {_one_line(item.get('checkId'))}: "
            f"{_one_line(item.get('message'))}"
        )


def render_audit_report(home: Path, envelope: dict[str, Any]) -> str:
    """Render a readable projection only from verified canonical audit evidence."""

    if not isinstance(envelope, dict) or envelope.get("artifactType") != "audit-result":
        raise RunArtifactIntegrityError("Readable audit reports require sealed audit-result evidence.")
    audit = verify_run_artifact(home, envelope)
    design_lane = audit.get("designSystemLane")
    ux_lane = audit.get("uxAccessibilityLane")
    coverage = audit.get("coverage")
    usage_lane = audit.get("usageRulesLane") if audit.get("schemaVersion") == 2 else None
    if not isinstance(design_lane, dict) or not isinstance(ux_lane, dict) or not isinstance(coverage, dict):
        raise RunArtifactIntegrityError("Audit lanes and coverage must be objects.")
    if audit.get("schemaVersion") == 2:
        if not isinstance(usage_lane, dict):
            raise RunArtifactIntegrityError("Usage Rules lane must be an object.")
        try:
            derive_audit_exit_code(audit)
        except AuditIntegrityError as error:
            raise RunArtifactIntegrityError(
                f"Usage Rules audit evidence is invalid: {error}"
            ) from error
    categories = coverage.get("categories")
    if not isinstance(categories, dict) or set(categories) != set(AUDIT_CATEGORIES):
        raise RunArtifactIntegrityError("Readable report requires all exact audit categories.")
    try:
        project = validate_project_evidence(audit.get("projectEvidence"))
    except ProjectBindingError as error:
        raise RunArtifactIntegrityError(f"Readable report project evidence is invalid: {error}") from error
    try:
        authority_lane = canonicalize_enforcement_authority_lane(
            audit.get("enforcementAuthorityLane")
        )
    except EnforcementAuthorityIntegrityError as error:
        raise RunArtifactIntegrityError(f"Readable report authority lane is invalid: {error}") from error
    adapter = coverage.get("adapter")
    if not isinstance(adapter, str) or not adapter:
        raise RunArtifactIntegrityError("Readable report adapter must be a non-empty string.")
    workspace_labels = _workspace_labels(adapter)
    lines = [
        "# Design System Guardian Audit",
        "",
        f"Run: {_one_line(audit.get('runId'))}",
        f"Profile: {_one_line(audit.get('profileId'))}",
        f"Snapshot: {_one_line(audit.get('snapshotId'))}",
        f"Policy: {_one_line(audit.get('policyDigest'))}",
        f"{workspace_labels['root']}: {_one_line(project['canonicalRoot'])}",
        f"{workspace_labels['identity']}: {_one_line(project['rootIdentity'])}",
        f"{workspace_labels['tree']}: {_one_line(project['assessedTreeDigest'])}",
        f"{workspace_labels['inputs']}: {_one_line(project['analysisInputsDigest'])}",
        f"{workspace_labels['commit']}: {_one_line(project['gitCommit'])}",
        "",
        "## Design-system compliance lane",
        "",
        f"Design-system compliance: {_one_line(design_lane.get('status'))}",
        f"Source cut: {_one_line(design_lane.get('sourceCutDigest'))}",
        f"Adapter: {_one_line(adapter)}",
        f"Adapter config: {_one_line(coverage.get('configDigest'))}",
        "",
        "### Coverage",
        "",
    ]
    for category in AUDIT_CATEGORIES:
        item = categories[category]
        if not isinstance(item, dict):
            raise RunArtifactIntegrityError(f"Coverage for {category} must be an object.")
        lines.append(
            f"- {category}: {_one_line(item.get('status'))} "
            f"({_one_line(item.get('assessedItems'))}/{_one_line(item.get('totalItems'))})"
        )
    for title, key in (("Violations", "violations"), ("Design-system gaps", "gaps")):
        values = design_lane.get(key)
        if not isinstance(values, list):
            raise RunArtifactIntegrityError(f"Audit {key} must be an array.")
        lines.extend(["", f"### {title}", ""])
        if not values:
            lines.append("None.")
        else:
            for item in values:
                if not isinstance(item, dict):
                    raise RunArtifactIntegrityError(f"Audit {key} entries must be objects.")
                lines.append(
                    f"- [{_one_line(item.get('category'))}] "
                    f"{_one_line(item.get('diagnosticId'))}: {_one_line(item.get('message'))}"
                )
    if usage_lane is not None:
        lines.extend(
            [
                "",
                "## Usage Rules compliance lane",
                "",
                f"Usage Rules compliance: {_one_line(usage_lane.get('status'))}",
                f"Evaluator: {_one_line(usage_lane.get('evaluatorId'))}",
                "",
                "### Active gating rules",
                "",
            ]
        )
        active_rule_ids = usage_lane.get("activeRuleIds")
        assessed_rule_ids = usage_lane.get("assessedRuleIds")
        violated_rule_ids = usage_lane.get("violatedRuleIds")
        informative_rule_ids = usage_lane.get("informativeRuleIds")
        not_assessed = usage_lane.get("notAssessed")
        usage_diagnostics = usage_lane.get("diagnostics")
        if not all(
            isinstance(value, list)
            for value in (
                active_rule_ids,
                assessed_rule_ids,
                violated_rule_ids,
                informative_rule_ids,
                not_assessed,
                usage_diagnostics,
            )
        ):
            raise RunArtifactIntegrityError(
                "Usage Rules lists must be canonical arrays."
            )
        lines.append(
            ", ".join(_one_line(item) for item in active_rule_ids)
            if active_rule_ids
            else "None."
        )
        lines.extend(["", "### Assessed rules", ""])
        lines.append(
            ", ".join(_one_line(item) for item in assessed_rule_ids)
            if assessed_rule_ids
            else "None."
        )
        lines.extend(["", "### Violated rules", ""])
        if usage_diagnostics:
            for item in usage_diagnostics:
                if not isinstance(item, dict):
                    raise RunArtifactIntegrityError(
                        "Usage Rules diagnostics must be objects."
                    )
                lines.append(
                    f"- {_one_line(item.get('ruleId'))}: "
                    f"{_one_line(item.get('reasonCode'))}"
                )
        else:
            lines.append("None.")
        lines.extend(["", "### Not assessed", ""])
        if not_assessed:
            for item in not_assessed:
                if not isinstance(item, dict):
                    raise RunArtifactIntegrityError(
                        "Usage Rules not-assessed entries must be objects."
                    )
                lines.append(
                    f"- {_one_line(item.get('ruleId'))}: "
                    f"{_one_line(item.get('reasonCode'))}"
                )
        else:
            lines.append("None.")
        lines.extend(["", "### Informative rules (non-gating)", ""])
        lines.append(
            ", ".join(_one_line(item) for item in informative_rule_ids)
            if informative_rule_ids
            else "None."
        )

    checks = ux_lane.get("checks")
    if not isinstance(checks, list):
        raise RunArtifactIntegrityError("UX/accessibility checks must be an array.")
    for item in checks:
        if not isinstance(item, dict):
            raise RunArtifactIntegrityError("UX/accessibility check entries must be objects.")
    screen_checks, flow_checks, legacy_checks = _ux_checks_by_scope(checks)
    lines.extend(
        [
            "",
            "## UX/accessibility quality lane" if usage_lane is not None else "## UX/accessibility lane",
            "",
            f"UX/accessibility: {_one_line(ux_lane.get('status'))}",
        ]
    )
    _append_checks(
        lines,
        title="Screen checks",
        checks=screen_checks,
        empty_message="Not assessed.",
    )
    _append_checks(
        lines,
        title="Final-flow checks",
        checks=flow_checks,
        empty_message="Not assessed.",
    )
    if legacy_checks:
        lines.extend(["", "Legacy evaluator status:", ""])
        for item in legacy_checks:
            lines.append(
                f"- [{_one_line(item.get('status'))}] {_one_line(item.get('checkId'))}: "
                f"{_one_line(item.get('message'))}"
            )
    lines.extend(
        [
            "",
            "## Protected production authority lane",
            "",
            f"Protected enforcement authority: {_one_line(authority_lane['status'])}",
            f"Authority provider: {_one_line(authority_lane['provider'])}",
            f"Authority attestation: {_one_line(authority_lane['attestation'])}",
            f"Production ready: {'yes' if audit.get('productionReady') is True else 'no'}",
            "",
            "## Next action",
            "",
            "Next action: "
            + _next_action(
                audit=audit,
                design_lane=design_lane,
                ux_lane=ux_lane,
                coverage=coverage,
                authority_lane=authority_lane,
                usage_lane=usage_lane,
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def render_judgment_report(status: dict[str, Any]) -> str:
    """Render the current verified judgment projection without storing it."""

    if not isinstance(status, dict):
        raise RunArtifactIntegrityError("Readable judgment status must be an object.")
    profile_id, run_id, state = (
        status.get("profileId"), status.get("runId"), status.get("status")
    )
    if not all(isinstance(value, str) and value for value in (profile_id, run_id, state)):
        raise RunArtifactIntegrityError("Readable judgment status identity is invalid.")
    assessment, projection = status.get("assessment"), status.get("effectiveProjection")
    if assessment is None and projection is None and state == "not_assessed":
        return "\n".join(
            [
                "# Guardian Judgment Report", "", f"Profile: {_one_line(profile_id)}",
                f"Run: {_one_line(run_id)}", "Judgment state: not_assessed",
                "Revocation state: unavailable", "Raw judgment: not_assessed",
                "Effective judgment: not_assessed",
                "Protected enforcement authority: not_assessed",
                "Production ready: false", "Selected finding IDs: None.",
                "Unselected finding IDs: None.", "",
                "No complete judgment assessment is available for this exact run.", "",
            ]
        )
    if not isinstance(assessment, dict) or not isinstance(projection, dict):
        raise RunArtifactIntegrityError(
            "Readable judgment status requires assessment and projection objects."
        )
    instances, projected_instances = assessment.get("instances"), projection.get("instances")
    if not isinstance(instances, list) or not isinstance(projected_instances, list):
        raise RunArtifactIntegrityError("Readable judgment instances must be arrays.")
    if len(instances) != len(projected_instances):
        raise RunArtifactIntegrityError("Readable judgment projections are incomplete.")
    projected_by_id = {
        item.get("instanceId"): item for item in projected_instances if isinstance(item, dict)
    }
    if len(projected_by_id) != len(projected_instances):
        raise RunArtifactIntegrityError("Readable projected judgment instances are invalid.")
    selected: list[str] = []
    for item in projected_instances:
        exceptions = item.get("appliedExceptions")
        if not isinstance(exceptions, list):
            raise RunArtifactIntegrityError("Readable judgment exceptions must be an array.")
        for exception in exceptions:
            if (
                not isinstance(exception, dict)
                or not isinstance(exception.get("findingId"), str)
                or exception.get("label") != "Passed through a user-approved exception"
            ):
                raise RunArtifactIntegrityError("Readable judgment exception is invalid.")
            selected.append(exception["findingId"])
    rows: list[tuple[dict[str, Any], dict[str, Any], bool]] = []
    finding_ids: list[str] = []
    for instance in instances:
        if not isinstance(instance, dict):
            raise RunArtifactIntegrityError("Readable judgment assessment instance is invalid.")
        projected = projected_by_id.get(instance.get("instanceId"))
        findings = instance.get("findings")
        if (
            not isinstance(projected, dict)
            or projected.get("rawStatus") != instance.get("rawStatus")
            or not isinstance(findings, list)
            or projected.get("findings") != findings
        ):
            raise RunArtifactIntegrityError("Readable judgment raw findings were not preserved.")
        for finding in findings:
            if not isinstance(finding, dict) or not isinstance(finding.get("findingId"), str):
                raise RunArtifactIntegrityError("Readable judgment finding is invalid.")
            finding_ids.append(finding["findingId"])
            rows.append((instance, finding, finding["findingId"] in selected))
    if len(selected) != len(set(selected)) or len(finding_ids) != len(set(finding_ids)):
        raise RunArtifactIntegrityError("Readable judgment finding IDs are not canonical.")
    selected = sorted(selected)
    finding_ids = sorted(finding_ids)
    if not set(selected).issubset(finding_ids):
        raise RunArtifactIntegrityError("Readable exceptions select unknown findings.")
    unselected = [item for item in finding_ids if item not in set(selected)]
    revocation = (
        "active exception; revocation available"
        if state == "active" and status.get("revocationPermissionBinding") is not None
        else "active exception; revocation unavailable" if state == "active"
        else "revoked" if state == "revoked" else _one_line(state)
    )
    production_ready = status.get("productionReady") is True
    if production_ready != (projection.get("productionReady") is True):
        raise RunArtifactIntegrityError("Readable production authority result is inconsistent.")
    lines = [
        "# Guardian Judgment Report", "", f"Profile: {_one_line(profile_id)}",
        f"Run: {_one_line(run_id)}", f"Judgment state: {_one_line(state)}",
        f"Revocation state: {revocation}",
        f"Raw judgment: {_one_line(assessment.get('rawStatus'))}",
        f"Effective judgment: {_one_line(projection.get('effectiveStatus'))}",
        "Protected enforcement authority: " + _one_line(projection.get("enforcementAuthorityStatus")),
        f"Production ready: {'true' if production_ready else 'false'}",
        "Selected finding IDs: " + (", ".join(selected) if selected else "None."),
        "Unselected finding IDs: " + (", ".join(unselected) if unselected else "None."),
        "", "## Original findings", "",
    ]
    if not rows:
        lines.append("None.")
    for instance, finding, is_selected in rows:
        lines.extend([
            f"### {_one_line(finding['findingId'])}", "",
            f"- Raw status: {_one_line(instance.get('rawStatus'))}",
            f"- Rule: {_one_line(finding.get('ruleId'))}",
            f"- Target: {_one_line(finding.get('targetId'))}",
            f"- Instance: {_one_line(instance.get('instanceId'))}",
            f"- What failed: {_one_line(finding.get('explanation'))}",
            f"- Why it matters: {_one_line(finding.get('impact'))}",
            f"- Recommended correction: {_one_line(finding.get('correction'))}",
        ])
        references = finding.get("evidenceReferences")
        if not isinstance(references, list) or not all(isinstance(item, dict) for item in references):
            raise RunArtifactIntegrityError("Readable finding evidence must be an array.")
        lines.append("- Evidence: " + (", ".join(
            f"{_one_line(item.get('artifact'))}@{_one_line(item.get('digest'))}" for item in references
        ) if references else "None."))
        if is_selected:
            lines.append("- Exception: Passed through a user-approved exception")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

def write_readable_report(home: Path, *, profile_id: str, run_id: str, report: str) -> Path:
    """Create a deterministic derived report once without rewriting history."""

    if not isinstance(report, str):
        raise RunArtifactIntegrityError("Readable report must be text.")
    normalized_home = home.expanduser().absolute()
    path = _report_path(normalized_home, profile_id=profile_id, run_id=run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(normalized_home, path)
    payload = report.encode("utf-8")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Readable report write did not make progress.")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise RunArtifactIntegrityError("Derived report history cannot be replaced or rewritten.")
    if path.read_bytes() != payload:
        raise RunArtifactIntegrityError("Derived report bytes changed during creation.")
    return path

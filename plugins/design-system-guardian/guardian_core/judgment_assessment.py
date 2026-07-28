"""Pure judgment assessment and effective-projection contracts for Guardian v0.3.7."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest
from .audit_attestation import verify_analysis_attestation

from .enforcement_authority import (
    EnforcementAuthorityIntegrityError,
    canonicalize_enforcement_authority_lane,
)
from .ux_evaluator import UxEvaluationIntegrityError, audit_checks_from_evaluation

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_STABLE_ID = re.compile(r"^(?:target|instance|finding)-[0-9a-f]{24}$")
_STATUSES = {"allowed", "conflict", "not_assessed"}
_CANDIDATE_KEYS = {"ruleId", "targetId", "status", "incompletenessReason", "findings"}
_FINDING_INPUT_KEYS = {"explanation", "impact", "evidenceReferences", "correction"}
_FINDING_KEYS = {
    "findingId", "ruleId", "targetId", "explanation", "impact",
    "evidenceReferences", "correction", "evidenceDigest",
}
_ASSESSMENT_KEYS = {
    "schemaVersion", "runId", "profileId", "bindings", "activeRuleIds",
    "target", "instances", "rawStatus", "complete", "nonJudgmentBlockersClear",
}
_BINDING_KEYS = {
    "runPinDigest", "profileDigest", "policyDigest", "snapshotDigest",
    "sourceCutDigest", "ruleSnapshotDigest", "activeRuleSetDigest",
    "evaluatorContractDigest", "analysisAttestationDigest", "auditResultDigest",
    "targetDigest", "evidenceDigest",
}
_INSTANCE_KEYS = {
    "instanceId", "source", "ruleId", "target", "rawStatus",
    "incompletenessReason", "findings",
}
_EXCEPTION_LABEL = "Passed through a user-approved exception"
JUDGMENT_EVALUATOR_CONTRACT_DIGEST = sha256_digest(
    {
        "schemaVersion": 1,
        "algorithmVersion": 1,
        "name": "design-system-guardian-judgment-assessment",
        "statuses": ["allowed", "conflict", "not_assessed"],
        "occurrenceKinds": ["category", "component", "icon", "token"],
        "exceptionLabel": _EXCEPTION_LABEL,
        "callerAuthority": False,
    }
)


class JudgmentAssessmentIntegrityError(ValueError):
    """Raised when judgment evidence, applicability, or authority is ambiguous."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise JudgmentAssessmentIntegrityError(f"{field} must be an object.")
    return value


def _exact(value: Mapping[str, Any], keys: set[str], field: str) -> None:
    if set(value) != keys:
        raise JudgmentAssessmentIntegrityError(f"{field} has unknown or missing fields.")


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise JudgmentAssessmentIntegrityError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _text(value: Any, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise JudgmentAssessmentIntegrityError(f"{field} must be bounded non-blank text.")
    return value


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 127 or not _SAFE_ID.fullmatch(value):
        raise JudgmentAssessmentIntegrityError(f"{field} is invalid.")
    return value


def _stable_id(prefix: str, payload: object) -> str:
    return f"{prefix}-{sha256_digest(payload)[:24]}"


def _target(details: dict[str, Any]) -> dict[str, Any]:
    return {
        "targetId": _stable_id("target", details),
        **copy.deepcopy(details),
        "digest": sha256_digest(details),
    }


def _aggregate(statuses: list[str]) -> str:
    if "conflict" in statuses:
        return "conflict"
    if "not_assessed" in statuses:
        return "not_assessed"
    return "allowed"


def _validate_applies_to(value: Any) -> dict[str, Any]:
    item = _mapping(value, "rule.appliesTo")
    kind = item.get("kind")
    if kind == "system":
        _exact(item, {"kind"}, "rule.appliesTo")
    elif kind == "category":
        _exact(item, {"kind", "category"}, "rule.appliesTo")
        _text(item.get("category"), "rule.appliesTo.category", 127)
    elif kind in {"component", "icon", "token"}:
        _exact(item, {"kind", "identity"}, "rule.appliesTo")
        _text(item.get("identity"), "rule.appliesTo.identity", 256)
    else:
        raise JudgmentAssessmentIntegrityError("Judgment rule appliesTo kind is invalid.")
    return copy.deepcopy(dict(item))


def _identity_inputs(run_pin: Any, rule_snapshot: Any, analysis: Any, audit: Any):
    pin = dict(_mapping(run_pin, "run_pin"))
    snapshot = dict(_mapping(rule_snapshot, "rule_snapshot"))
    attestation = dict(_mapping(analysis, "analysis_attestation"))
    audit_result = dict(_mapping(audit, "audit_result"))
    if pin.get("schemaVersion") not in {1, 2} or snapshot.get("schemaVersion") != 2:
        raise JudgmentAssessmentIntegrityError("Run pin or rule snapshot version is invalid.")
    _text(pin.get("runId"), "run_pin.runId", 128)
    _text(pin.get("profileId"), "run_pin.profileId", 128)
    for field in ("profileDigest", "snapshotId", "catalogDigest", "policyDigest"):
        _digest(pin.get(field), f"run_pin.{field}")
    if not isinstance(pin.get("sourceCut"), Mapping) or not pin["sourceCut"]:
        raise JudgmentAssessmentIntegrityError("run_pin.sourceCut must be non-empty.")
    for field in ("profileId", "profileDigest", "snapshotId", "catalogDigest", "policyDigest"):
        if snapshot.get(field) != pin.get(field):
            raise JudgmentAssessmentIntegrityError(f"Rule snapshot {field} is mismatched.")
    rules = snapshot.get("rules")
    if not isinstance(rules, list) or len(rules) > 4096:
        raise JudgmentAssessmentIntegrityError("Rule snapshot rules are invalid.")
    if snapshot.get("rulesDigest") != sha256_digest(rules):
        raise JudgmentAssessmentIntegrityError("Rule snapshot rulesDigest is invalid.")
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        if attestation.get(field) != pin.get(field) or audit_result.get(field) != pin.get(field):
            raise JudgmentAssessmentIntegrityError(f"Analysis or audit {field} is mismatched.")
    attested_audit = audit_result
    if audit_result.get("schemaVersion") == 2:
        if "usageRulesLane" not in audit_result:
            raise JudgmentAssessmentIntegrityError(
                "Audit-result v2 lacks its Usage Rules lane."
            )
        attested_audit = copy.deepcopy(audit_result)
        attested_audit["schemaVersion"] = 1
        attested_audit.pop("usageRulesLane")
    if attestation.get("auditResultDigest") != sha256_digest(attested_audit):
        raise JudgmentAssessmentIntegrityError("Analysis is not bound to the audit result.")
    runner = _mapping(attestation.get("runnerEvidence"), "analysis.runnerEvidence")
    if attestation.get("runnerEvidenceDigest") != sha256_digest(runner):
        raise JudgmentAssessmentIntegrityError("Runner evidence digest is invalid.")
    return pin, snapshot, attestation, audit_result


def _active_rules(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    active = []
    seen = set()
    for index, raw in enumerate(snapshot["rules"]):
        rule = _mapping(raw, f"rules[{index}]")
        rule_id = _safe_id(rule.get("ruleId"), f"rules[{index}].ruleId")
        if rule_id in seen:
            raise JudgmentAssessmentIntegrityError("Rule IDs must be unique.")
        seen.add(rule_id)
        if rule.get("class") == "judgment":
            active.append({"ruleId": rule_id, "appliesTo": _validate_applies_to(rule.get("appliesTo"))})
    return active


def _final_flow(attestation: Mapping[str, Any], source_cut: Mapping[str, Any]):
    target = attestation.get("uxTarget")
    evaluation = attestation.get("uxEvaluation")
    if target is None and evaluation is None:
        return None, []
    if not isinstance(target, Mapping) or not isinstance(evaluation, Mapping):
        raise JudgmentAssessmentIntegrityError("Final-flow evidence is incomplete.")
    if set(target) != {"flowDigest", "screenDigests"}:
        raise JudgmentAssessmentIntegrityError("Final-flow target shape is invalid.")
    flow = _digest(target.get("flowDigest"), "uxTarget.flowDigest")
    screens = target.get("screenDigests")
    if not isinstance(screens, list) or not screens or len(screens) > 256 or len(screens) != len(set(screens)):
        raise JudgmentAssessmentIntegrityError("uxTarget.screenDigests is invalid.")
    for index, value in enumerate(screens):
        _digest(value, f"uxTarget.screenDigests[{index}]")
    if evaluation.get("scope") != "final_flow":
        raise JudgmentAssessmentIntegrityError("Only final-flow UX evidence is applicable.")
    if evaluation.get("targetDigest") != sha256_digest(target):
        raise JudgmentAssessmentIntegrityError("UX target binding is invalid.")
    if evaluation.get("sourceCutDigest") != sha256_digest(source_cut):
        raise JudgmentAssessmentIntegrityError("UX source-cut binding is invalid.")
    if attestation.get("uxEvaluationDigest") != sha256_digest(evaluation):
        raise JudgmentAssessmentIntegrityError("UX evaluation digest is invalid.")
    try:
        audit_checks_from_evaluation(evaluation, target=target, source_cut=source_cut)
    except UxEvaluationIntegrityError as error:
        raise JudgmentAssessmentIntegrityError(f"Sealed UX evaluation is invalid: {error}") from error
    return _target(
        {"kind": "system", "scope": "final_flow", "flowDigest": flow, "screenDigests": copy.deepcopy(screens)}
    ), copy.deepcopy(evaluation["checks"])


def _occurrences(
    attestation: Mapping[str, Any],
    *,
    run_pin: Mapping[str, Any],
    rule_snapshot: Mapping[str, Any],
    audit_result: Mapping[str, Any],
) -> list[dict[str, Any]] | None:
    runner = _mapping(attestation["runnerEvidence"], "analysis.runnerEvidence")
    raw = runner.get("adapterResult")
    if runner.get("adapter") != "figma" or not isinstance(raw, Mapping):
        return None
    try:
        verified = verify_analysis_attestation(
            dict(attestation),
            run_pin=run_pin,
            config_digest=_digest(
                attestation.get("configDigest"),
                "analysis_attestation.configDigest",
            ),
            audit_result=audit_result,
            verified_snapshot=rule_snapshot,
        )
    except (KeyError, TypeError, ValueError):
        return None
    runner = _mapping(verified["runnerEvidence"], "verified analysis.runnerEvidence")
    raw = _mapping(runner.get("adapterResult"), "verified analysis.adapterResult")
    source, analysis, observations = raw.get("source"), raw.get("analysis"), raw.get("observations")
    if (
        not isinstance(source, Mapping) or source.get("complete") is not True
        or not isinstance(analysis, Mapping) or analysis.get("complete") is not True
        or not isinstance(observations, list)
    ):
        return None
    counts = [analysis.get(key) for key in ("assessedNodes", "totalNodes", "assessedFields", "totalFields")]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
        return None
    if counts[0] != counts[1] or counts[2] != counts[3] or counts[2] != len(observations):
        return None
    output, locators = [], set()
    for index, raw_item in enumerate(observations):
        item = _mapping(raw_item, f"observations[{index}]")
        for field in ("category", "nodeId", "field"):
            _text(item.get(field), f"observations[{index}].{field}", 256)
        identity = item.get("identity")
        if identity is not None:
            _text(identity, f"observations[{index}].identity", 256)
        text_range = item.get("range")
        if text_range is not None:
            text_range = _mapping(text_range, f"observations[{index}].range")
            _exact(text_range, {"start", "end"}, f"observations[{index}].range")
            start, end = text_range.get("start"), text_range.get("end")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or start < 0
                or isinstance(end, bool)
                or not isinstance(end, int)
                or end <= start
            ):
                raise JudgmentAssessmentIntegrityError(
                    "Verified occurrence range is invalid."
                )
            text_range = {"start": start, "end": end}
        locator = canonical_json_bytes(
            {
                "category": item["category"],
                "nodeId": item["nodeId"],
                "field": item["field"],
                "range": text_range,
            }
        )
        if locator in locators:
            raise JudgmentAssessmentIntegrityError("Occurrence inventory has a duplicate locator.")
        locators.add(locator)
        output.append(
            {
                "category": item["category"], "nodeId": item["nodeId"], "field": item["field"],
                "identity": identity, "range": text_range,
                "observationKind": item.get("kind"),
            }
        )
    if len({item["nodeId"] for item in output}) != counts[0]:
        return None
    return sorted(output, key=canonical_json_bytes)


def _rule_targets(rule: Mapping[str, Any], system_target, inventory):
    applies = rule["appliesTo"]
    kind = applies["kind"]
    if kind == "system":
        if system_target is not None:
            return [system_target]
        return [_target({"kind": "coverage", "scope": "rule", "appliesTo": applies})]
    if inventory is None:
        return [_target({"kind": "coverage", "scope": "rule", "appliesTo": applies})]
    output = []
    for item in inventory:
        if kind == "category":
            matches = item["category"] == applies["category"]
        elif kind == "component":
            matches = item["category"] == "components" and item["identity"] == applies["identity"] and item["observationKind"] == "asset"
        elif kind == "icon":
            matches = item["category"] == "icons" and item["identity"] == applies["identity"] and item["observationKind"] == "asset"
        else:
            matches = item["identity"] == applies["identity"] and item["observationKind"] in {"variable", "style"}
        if matches:
            output.append(
                _target(
                    {
                        "kind": "occurrence", "scope": "occurrence",
                        "category": item["category"], "nodeId": item["nodeId"],
                        "field": item["field"], "identity": item["identity"],
                        "range": copy.deepcopy(item["range"]),
                    }
                )
            )
    return sorted(output, key=lambda value: value["targetId"])


def _finding(value: Any, rule_id: str, target_id: str) -> dict[str, Any]:
    item = _mapping(value, "candidate finding")
    _exact(item, _FINDING_INPUT_KEYS, "candidate finding")
    references = item.get("evidenceReferences")
    if not isinstance(references, list) or not references or len(references) > 32:
        raise JudgmentAssessmentIntegrityError("Finding references must contain 1 to 32 items.")
    normalized = []
    for index, raw in enumerate(references):
        ref = _mapping(raw, f"finding.references[{index}]")
        _exact(ref, {"artifact", "digest"}, f"finding.references[{index}]")
        normalized.append(
            {
                "artifact": _text(ref.get("artifact"), f"finding.references[{index}].artifact", 128),
                "digest": _digest(ref.get("digest"), f"finding.references[{index}].digest"),
            }
        )
    normalized.sort(key=canonical_json_bytes)
    if len({canonical_json_bytes(ref) for ref in normalized}) != len(normalized):
        raise JudgmentAssessmentIntegrityError("Finding references must be unique.")
    content = {
        "ruleId": rule_id, "targetId": target_id,
        "explanation": _text(item.get("explanation"), "finding.explanation"),
        "impact": _text(item.get("impact"), "finding.impact"),
        "evidenceReferences": normalized,
        "correction": _text(item.get("correction"), "finding.correction"),
    }
    return {
        "findingId": _stable_id("finding", content), **content,
        "evidenceDigest": sha256_digest(normalized),
    }


def _instance(rule_id: str, target: dict[str, Any], candidate: Mapping[str, Any] | None):
    target_id = target["targetId"]
    if candidate is None:
        status, reason, findings = "not_assessed", "candidate_result_unavailable", []
    else:
        status, reason, raw_findings = (
            candidate.get("status"), candidate.get("incompletenessReason"), candidate.get("findings")
        )
        if status not in _STATUSES or not isinstance(raw_findings, list) or len(raw_findings) > 256:
            raise JudgmentAssessmentIntegrityError("Candidate result is invalid.")
        findings = sorted(
            [_finding(value, rule_id, target_id) for value in raw_findings],
            key=lambda value: value["findingId"],
        )
        if len({value["findingId"] for value in findings}) != len(findings):
            raise JudgmentAssessmentIntegrityError("Finding IDs collide.")
        if status == "allowed" and (findings or reason is not None):
            raise JudgmentAssessmentIntegrityError("Allowed result has conflict fields.")
        if status == "conflict" and (not findings or reason is not None):
            raise JudgmentAssessmentIntegrityError("Conflict result lacks exact findings.")
        if status == "not_assessed":
            if findings:
                raise JudgmentAssessmentIntegrityError("Not-assessed result has findings.")
            reason = _text(reason, "candidate.incompletenessReason", 512)
    stable = {"source": "company_rule", "ruleId": rule_id, "targetId": target_id}
    return {
        "instanceId": _stable_id("instance", stable), "source": "company_rule",
        "ruleId": rule_id, "target": copy.deepcopy(target), "rawStatus": status,
        "incompletenessReason": reason, "findings": findings,
    }


def _coverage_instance(rule_id: str, target: dict[str, Any]):
    stable = {"source": "company_rule", "ruleId": rule_id, "targetId": target["targetId"]}
    reason = (
        "sealed_final_flow_target_unavailable"
        if target["appliesTo"]["kind"] == "system"
        else "sealed_occurrence_inventory_unavailable"
    )
    return {
        "instanceId": _stable_id("instance", stable), "source": "company_rule",
        "ruleId": rule_id, "target": copy.deepcopy(target), "rawStatus": "not_assessed",
        "incompletenessReason": reason, "findings": [],
    }


def _ux_instance(check: Mapping[str, Any]):
    scope = check.get("targetScope")
    if scope not in {"screen", "flow"}:
        raise JudgmentAssessmentIntegrityError("UX check scope is invalid.")
    check_id = _text(check.get("checkId"), "ux.checkId", 128)
    area = _text(check.get("area"), "ux.area", 128)
    target = _target(
        {
            "kind": "ux_check", "scope": scope,
            "targetDigest": _digest(check.get("targetDigest"), "ux.targetDigest"),
            "checkId": check_id, "area": area,
        }
    )
    source_status = check.get("status")
    if source_status == "gap":
        status, reason = "conflict", None
        evidence_digest = _digest(check.get("evidenceDigest"), "ux.evidenceDigest")
        findings = [
            _finding(
                {
                    "explanation": f"The inherited UX check reported a gap for {area}.",
                    "impact": "The final flow does not satisfy this required UX or accessibility check.",
                    "evidenceReferences": [{"artifact": "ux-evaluation", "digest": evidence_digest}],
                    "correction": "Correct the reported UX gap and evaluate the exact final flow again.",
                },
                "guardian.inherited-ux",
                target["targetId"],
            )
        ]
    elif source_status == "allowed":
        status, reason, findings = "allowed", None, []
    elif source_status == "not_assessed":
        status, reason, findings = "not_assessed", _text(check.get("reasonCode"), "ux.reasonCode", 128), []
    else:
        raise JudgmentAssessmentIntegrityError("UX check status is unsupported.")
    stable = {"source": "inherited_ux", "ruleId": "guardian.inherited-ux", "targetId": target["targetId"]}
    return {
        "instanceId": _stable_id("instance", stable), "source": "inherited_ux",
        "ruleId": "guardian.inherited-ux", "target": target, "rawStatus": status,
        "incompletenessReason": reason, "findings": findings,
    }


def _candidate_map(value: Any, targets_by_rule):
    if not isinstance(value, list) or len(value) > 4096:
        raise JudgmentAssessmentIntegrityError("candidate_results must be bounded.")
    output = {}
    for index, raw in enumerate(value):
        item = _mapping(raw, f"candidate_results[{index}]")
        _exact(item, _CANDIDATE_KEYS, f"candidate_results[{index}]")
        rule_id = _safe_id(item.get("ruleId"), f"candidate_results[{index}].ruleId")
        targets = [target for target in targets_by_rule.get(rule_id, []) if target["kind"] != "coverage"]
        target_id = item.get("targetId")
        if target_id is None:
            if len(targets) != 1:
                raise JudgmentAssessmentIntegrityError("Candidate needs one derived target.")
            target_id = targets[0]["targetId"]
        if not isinstance(target_id, str) or not _STABLE_ID.fullmatch(target_id):
            raise JudgmentAssessmentIntegrityError("Candidate targetId is invalid.")
        if target_id not in {target["targetId"] for target in targets}:
            raise JudgmentAssessmentIntegrityError("Candidate target is not applicable.")
        key = (rule_id, target_id)
        if key in output:
            raise JudgmentAssessmentIntegrityError("Candidate instance is duplicated.")
        output[key] = dict(item)
    return output


def _blockers_clear(audit: Mapping[str, Any]) -> bool:
    design, coverage, usage = audit.get("designSystemLane"), audit.get("coverage"), audit.get("usageRulesLane")
    return (
        isinstance(design, Mapping) and design.get("status") == "allowed"
        and isinstance(coverage, Mapping) and coverage.get("status") == "allowed"
        and (usage is None or isinstance(usage, Mapping) and usage.get("status") == "allowed")
    )


def build_judgment_assessment(
    *, run_pin: dict[str, object], rule_snapshot: dict[str, object],
    analysis_attestation: dict[str, object], audit_result: dict[str, object],
    candidate_results: list[dict[str, object]],
) -> dict[str, object]:
    pin, snapshot, attestation, audit = _identity_inputs(
        run_pin, rule_snapshot, analysis_attestation, audit_result
    )
    rules = _active_rules(snapshot)
    active_ids = [rule["ruleId"] for rule in rules]
    system_target, ux_checks = _final_flow(attestation, pin["sourceCut"])
    inventory = _occurrences(
        attestation,
        run_pin=pin,
        rule_snapshot=snapshot,
        audit_result=audit,
    )
    targets = {
        rule["ruleId"]: _rule_targets(rule, system_target, inventory) for rule in rules
    }
    candidates = _candidate_map(candidate_results, targets)
    instances = []
    for rule in rules:
        for target in targets[rule["ruleId"]]:
            if target["kind"] == "coverage":
                instances.append(_coverage_instance(rule["ruleId"], target))
            else:
                instances.append(
                    _instance(
                        rule["ruleId"], target,
                        candidates.pop((rule["ruleId"], target["targetId"]), None),
                    )
                )
    if candidates:
        raise JudgmentAssessmentIntegrityError("Candidate results contain unknown instances.")
    instances.extend(_ux_instance(check) for check in ux_checks)
    instances.sort(key=lambda value: value["instanceId"])
    if len({value["instanceId"] for value in instances}) != len(instances):
        raise JudgmentAssessmentIntegrityError("Instance IDs collide.")
    target_value = (
        copy.deepcopy(dict(attestation["uxTarget"]))
        if isinstance(attestation.get("uxTarget"), Mapping)
        else {"flowDigest": None, "screenDigests": []}
    )
    bindings = {
        "runPinDigest": sha256_digest(pin), "profileDigest": pin["profileDigest"],
        "policyDigest": pin["policyDigest"], "snapshotDigest": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "ruleSnapshotDigest": sha256_digest(snapshot),
        "activeRuleSetDigest": sha256_digest(active_ids),
        "evaluatorContractDigest": JUDGMENT_EVALUATOR_CONTRACT_DIGEST,
        "analysisAttestationDigest": sha256_digest(attestation),
        "auditResultDigest": sha256_digest(audit),
        "targetDigest": sha256_digest(target_value),
        "evidenceDigest": sha256_digest(
            {
                "runnerEvidenceDigest": attestation["runnerEvidenceDigest"],
                "uxEvaluationDigest": attestation.get("uxEvaluationDigest"),
                "auditResultDigest": attestation["auditResultDigest"],
            }
        ),
    }
    return {
        "schemaVersion": 1, "runId": pin["runId"], "profileId": pin["profileId"],
        "bindings": bindings, "activeRuleIds": active_ids, "target": target_value,
        "instances": instances,
        "rawStatus": _aggregate([value["rawStatus"] for value in instances]),
        "complete": all(value["rawStatus"] != "not_assessed" for value in instances),
        "nonJudgmentBlockersClear": _blockers_clear(audit),
    }


def _validate_target(value: Any) -> dict[str, Any]:
    item = _mapping(value, "target")
    kind = item.get("kind")
    expected = {
        "system": {"targetId", "kind", "scope", "flowDigest", "screenDigests", "digest"},
        "coverage": {"targetId", "kind", "scope", "appliesTo", "digest"},
        "occurrence": {
            "targetId", "kind", "scope", "category", "nodeId", "field",
            "identity", "range", "digest"
        },
        "ux_check": {
            "targetId", "kind", "scope", "targetDigest", "checkId", "area", "digest"
        },
    }.get(kind)
    if expected is None:
        raise JudgmentAssessmentIntegrityError("Target kind is unsupported.")
    _exact(item, expected, "target")
    details = {key: copy.deepcopy(value) for key, value in item.items() if key not in {"targetId", "digest"}}
    if item.get("targetId") != _stable_id("target", details) or item.get("digest") != sha256_digest(details):
        raise JudgmentAssessmentIntegrityError("Target identity is not derived.")
    if kind == "system":
        if item.get("scope") != "final_flow":
            raise JudgmentAssessmentIntegrityError("System scope is invalid.")
        _digest(item.get("flowDigest"), "target.flowDigest")
        screens = item.get("screenDigests")
        if not isinstance(screens, list) or not screens or len(screens) != len(set(screens)):
            raise JudgmentAssessmentIntegrityError("System screens are invalid.")
        for value in screens:
            _digest(value, "target.screenDigest")
    elif kind == "coverage":
        if item.get("scope") != "rule":
            raise JudgmentAssessmentIntegrityError("Coverage scope is invalid.")
        _validate_applies_to(item.get("appliesTo"))
    elif kind == "occurrence":
        if item.get("scope") != "occurrence":
            raise JudgmentAssessmentIntegrityError("Occurrence scope is invalid.")
        for field in ("category", "nodeId", "field"):
            _text(item.get(field), f"target.{field}", 256)
        if item.get("identity") is not None:
            _text(item.get("identity"), "target.identity", 256)
        text_range = item.get("range")
        if text_range is not None:
            text_range = _mapping(text_range, "target.range")
            _exact(text_range, {"start", "end"}, "target.range")
            start, end = text_range.get("start"), text_range.get("end")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or start < 0
                or isinstance(end, bool)
                or not isinstance(end, int)
                or end <= start
            ):
                raise JudgmentAssessmentIntegrityError("Target range is invalid.")
    else:
        if item.get("scope") not in {"screen", "flow"}:
            raise JudgmentAssessmentIntegrityError("UX target scope is invalid.")
        _digest(item.get("targetDigest"), "target.targetDigest")
        _text(item.get("checkId"), "target.checkId", 128)
        _text(item.get("area"), "target.area", 128)
    return copy.deepcopy(dict(item))


def _validate_assessment(value: Any) -> dict[str, Any]:
    assessment = _mapping(value, "assessment")
    _exact(assessment, _ASSESSMENT_KEYS, "assessment")
    if assessment.get("schemaVersion") != 1:
        raise JudgmentAssessmentIntegrityError("Assessment version is invalid.")
    _text(assessment.get("runId"), "assessment.runId", 128)
    _text(assessment.get("profileId"), "assessment.profileId", 128)
    bindings = _mapping(assessment.get("bindings"), "assessment.bindings")
    _exact(bindings, _BINDING_KEYS, "assessment.bindings")
    for field in _BINDING_KEYS:
        _digest(bindings.get(field), f"assessment.bindings.{field}")
    active = assessment.get("activeRuleIds")
    if not isinstance(active, list) or len(active) > 4096 or len(active) != len(set(active)):
        raise JudgmentAssessmentIntegrityError("Active rule IDs are invalid.")
    for rule_id in active:
        _safe_id(rule_id, "assessment.activeRuleId")
    target = assessment.get("target")
    if not isinstance(target, Mapping) or set(target) != {"flowDigest", "screenDigests"}:
        raise JudgmentAssessmentIntegrityError("Assessment final-flow target is invalid.")
    if target.get("flowDigest") is not None:
        _digest(target.get("flowDigest"), "assessment.target.flowDigest")
    screens = target.get("screenDigests")
    if not isinstance(screens, list) or len(screens) > 256 or len(screens) != len(set(screens)):
        raise JudgmentAssessmentIntegrityError("Assessment screenDigests are invalid.")
    for digest in screens:
        _digest(digest, "assessment.target.screenDigest")
    raw_instances = assessment.get("instances")
    if not isinstance(raw_instances, list) or len(raw_instances) > 8192:
        raise JudgmentAssessmentIntegrityError("Assessment instances are invalid.")
    instances, instance_ids, finding_ids = [], [], set()
    for raw in raw_instances:
        item = _mapping(raw, "assessment instance")
        _exact(item, _INSTANCE_KEYS, "assessment instance")
        source = item.get("source")
        if source not in {"company_rule", "inherited_ux"}:
            raise JudgmentAssessmentIntegrityError("Instance source is invalid.")
        rule_id = _safe_id(item.get("ruleId"), "assessment instance ruleId")
        target_item = _validate_target(item.get("target"))
        expected_id = _stable_id(
            "instance", {"source": source, "ruleId": rule_id, "targetId": target_item["targetId"]}
        )
        if item.get("instanceId") != expected_id:
            raise JudgmentAssessmentIntegrityError("Instance ID is not derived.")
        status, reason, raw_findings = (
            item.get("rawStatus"), item.get("incompletenessReason"), item.get("findings")
        )
        if status not in _STATUSES or not isinstance(raw_findings, list) or len(raw_findings) > 256:
            raise JudgmentAssessmentIntegrityError("Instance status or findings are invalid.")
        findings = []
        for raw_finding in raw_findings:
            finding = _mapping(raw_finding, "assessment finding")
            _exact(finding, _FINDING_KEYS, "assessment finding")
            if finding.get("ruleId") != rule_id or finding.get("targetId") != target_item["targetId"]:
                raise JudgmentAssessmentIntegrityError("Finding identity is mismatched.")
            expected_finding = _finding(
                {key: copy.deepcopy(finding[key]) for key in _FINDING_INPUT_KEYS},
                rule_id,
                target_item["targetId"],
            )
            if finding != expected_finding or finding["findingId"] in finding_ids:
                raise JudgmentAssessmentIntegrityError("Finding identity is invalid.")
            finding_ids.add(finding["findingId"])
            findings.append(dict(finding))
        if [value["findingId"] for value in findings] != sorted(value["findingId"] for value in findings):
            raise JudgmentAssessmentIntegrityError("Findings are not canonical.")
        if status == "allowed" and (findings or reason is not None):
            raise JudgmentAssessmentIntegrityError("Allowed instance shape is invalid.")
        if status == "conflict" and (not findings or reason is not None):
            raise JudgmentAssessmentIntegrityError("Conflict instance shape is invalid.")
        if status == "not_assessed":
            _text(reason, "instance.incompletenessReason", 512)
            if findings:
                raise JudgmentAssessmentIntegrityError("Not-assessed instance shape is invalid.")
        instances.append(dict(item))
        instance_ids.append(expected_id)
    if instance_ids != sorted(instance_ids) or len(instance_ids) != len(set(instance_ids)):
        raise JudgmentAssessmentIntegrityError("Instances are not uniquely canonical.")
    if assessment.get("rawStatus") != _aggregate([item["rawStatus"] for item in instances]):
        raise JudgmentAssessmentIntegrityError("Aggregate rawStatus is invalid.")
    complete = all(item["rawStatus"] != "not_assessed" for item in instances)
    if assessment.get("complete") is not complete:
        raise JudgmentAssessmentIntegrityError("Completeness is invalid.")
    if not isinstance(assessment.get("nonJudgmentBlockersClear"), bool):
        raise JudgmentAssessmentIntegrityError("Blocker state must be boolean.")
    if bindings.get("activeRuleSetDigest") != sha256_digest(active):
        raise JudgmentAssessmentIntegrityError("Active-rule binding is invalid.")
    if bindings.get("evaluatorContractDigest") != JUDGMENT_EVALUATOR_CONTRACT_DIGEST:
        raise JudgmentAssessmentIntegrityError("Evaluator binding is invalid.")
    if bindings.get("targetDigest") != sha256_digest(target):
        raise JudgmentAssessmentIntegrityError("Target binding is invalid.")
    return copy.deepcopy(dict(assessment))


def validate_judgment_assessment(
    assessment: object, *, run_pin: dict[str, object], rule_snapshot: dict[str, object],
    analysis_attestation: dict[str, object], audit_result: dict[str, object],
) -> dict[str, object]:
    normalized = _validate_assessment(assessment)
    candidates = []
    for item in normalized["instances"]:
        if item["source"] != "company_rule" or item["target"]["kind"] == "coverage":
            continue
        candidates.append(
            {
                "ruleId": item["ruleId"], "targetId": item["target"]["targetId"],
                "status": item["rawStatus"], "incompletenessReason": item["incompletenessReason"],
                "findings": [
                    {key: copy.deepcopy(finding[key]) for key in _FINDING_INPUT_KEYS}
                    for finding in item["findings"]
                ],
            }
        )
    expected = build_judgment_assessment(
        run_pin=run_pin, rule_snapshot=rule_snapshot,
        analysis_attestation=analysis_attestation, audit_result=audit_result,
        candidate_results=candidates,
    )
    if normalized != expected:
        raise JudgmentAssessmentIntegrityError("Assessment differs from recomputation.")
    return normalized


def derive_effective_judgment(
    assessment: dict[str, object], decision_state: dict[str, object] | None, *,
    enforcement_authority_lane: dict[str, object],
) -> dict[str, object]:
    normalized = _validate_assessment(assessment)
    selected = set()
    decision_active = False
    if decision_state is not None:
        decision = _mapping(decision_state, "decision_state")
        _exact(decision, {"active", "assessmentDigest", "selectedFindingIds"}, "decision_state")
        if not isinstance(decision.get("active"), bool):
            raise JudgmentAssessmentIntegrityError("Decision active flag is invalid.")
        if decision.get("assessmentDigest") != sha256_digest(normalized):
            raise JudgmentAssessmentIntegrityError("Decision assessment binding is invalid.")
        values = decision.get("selectedFindingIds")
        if (
            not isinstance(values, list) or len(values) > 8192
            or values != sorted(values) or len(values) != len(set(values))
        ):
            raise JudgmentAssessmentIntegrityError("Selected finding IDs are not canonical.")
        if any(not isinstance(value, str) or not _STABLE_ID.fullmatch(value) for value in values):
            raise JudgmentAssessmentIntegrityError("Selected finding ID is invalid.")
        if decision["active"]:
            decision_active = True
            selected = set(values)
        elif values:
            raise JudgmentAssessmentIntegrityError("Inactive decision selects findings.")
    conflicts = {
        finding["findingId"]
        for item in normalized["instances"] if item["rawStatus"] == "conflict"
        for finding in item["findings"]
    }
    if not selected.issubset(conflicts):
        raise JudgmentAssessmentIntegrityError("Only conflict findings may be excepted.")
    try:
        authority = canonicalize_enforcement_authority_lane(enforcement_authority_lane)
    except EnforcementAuthorityIntegrityError as error:
        raise JudgmentAssessmentIntegrityError(str(error)) from error
    projected, statuses = [], []
    for item in normalized["instances"]:
        ids = {finding["findingId"] for finding in item["findings"]}
        if item["rawStatus"] == "allowed":
            effective = "allowed" if decision_active else "not_assessed"
        elif (
            item["rawStatus"] == "conflict"
            and decision_active
            and ids
            and ids.issubset(selected)
        ):
            effective = "allowed"
        else:
            effective = item["rawStatus"]
        statuses.append(effective)
        projected.append(
            {
                "instanceId": item["instanceId"], "rawStatus": item["rawStatus"],
                "effectiveStatus": effective, "findings": copy.deepcopy(item["findings"]),
                "appliedExceptions": [
                    {"findingId": finding_id, "label": _EXCEPTION_LABEL}
                    for finding_id in sorted(ids & selected)
                ],
            }
        )
    effective = _aggregate(statuses)
    return {
        "schemaVersion": 1, "assessmentDigest": sha256_digest(normalized),
        "rawStatus": normalized["rawStatus"], "effectiveStatus": effective,
        "complete": normalized["complete"],
        "nonJudgmentBlockersClear": normalized["nonJudgmentBlockersClear"],
        "enforcementAuthorityStatus": authority["status"],
        "productionReady": (
            effective == "allowed" and normalized["complete"]
            and normalized["nonJudgmentBlockersClear"] and authority.get("status") == "allowed"
        ),
        "instances": projected,
    }


__all__ = [
    "JUDGMENT_EVALUATOR_CONTRACT_DIGEST", "JudgmentAssessmentIntegrityError",
    "build_judgment_assessment", "derive_effective_judgment",
    "validate_judgment_assessment",
]

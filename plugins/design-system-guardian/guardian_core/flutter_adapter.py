"""Strict boundary from the shipped Flutter analyzer contract to audit evidence."""

from __future__ import annotations

import copy
import re
from pathlib import PurePosixPath
from typing import Any, Mapping

from .audit import AUDIT_CATEGORIES
from .canonical import canonical_json_bytes, sha256_digest
from .contracts import ExitCode
from .flutter_packages import (
    FlutterPackageProvenanceError,
    validate_approved_package_bindings,
    validate_required_package_bindings,
)
from .flutter_toolchain import (
    FlutterToolchainIntegrityError,
    current_platform_id,
    validate_toolchain_binding,
)


class FlutterAdapterIntegrityError(ValueError):
    """Raised when Flutter evidence cannot be proved against one run and config."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


_TOP_KEYS = {
    "schemaVersion",
    "adapter",
    "adapterVersion",
    "status",
    "binding",
    "analysis",
    "diagnostics",
    "coverage",
    "suppressionScan",
    "productionReady",
}
_CONFIG_V1_KEYS = {
    "schemaVersion",
    "adapter",
    "adapterVersion",
    "toolchain",
    "requiredPackages",
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "configDigest",
    "approvedPackages",
    "approvedIdentities",
    "componentVariants",
}
_CONFIG_V2_KEYS = _CONFIG_V1_KEYS | {
    "ruleSnapshotId",
    "rulesDigest",
    "activeUsageRules",
    "usageRuleCoverage",
}
_BINDING_KEYS = {
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "configDigest",
}
_ANALYSIS_KEYS = {"method", "complete", "assessedFiles", "totalFiles"}
_LANE_KEYS = {"status", "method", "diagnosticCount"}
_DIAGNOSTIC_KEYS = {"severity", "code", "path", "line", "column", "length", "message"}
_SCAN_KEYS = {"schemaVersion", "method", "astProof", "findings"}
_FINDING_KEYS = {"path", "line", "text", "kind"}
_IDENTITY_CATEGORIES = {
    "colors",
    "textStyles",
    "icons",
    "dimensions",
    "effects",
    "motion",
    "widgets",
}
_CODE_CATEGORIES = {
    "guardian_unapproved_widget": ("components",),
    "guardian_unapproved_visual_primitive": ("components",),
    "guardian_unapproved_component_variant": ("components",),
    "guardian_usage_rule": ("components",),
    "guardian_sentinel_present": ("components",),
    "guardian_unapproved_icon": ("icons",),
    "guardian_unapproved_color": ("colors",),
    "guardian_unapproved_text_style": ("typography",),
    "guardian_unapproved_dimension": ("spacing",),
    "guardian_unapproved_radius": ("radii",),
    "guardian_unapproved_effect": ("effects",),
    "guardian_unapproved_motion": ("motion",),
    "guardian_suppression_forbidden": AUDIT_CATEGORIES,
}
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_CODE_IDENTITY = re.compile(r"^(?:dart|package):[^#\s]+#[A-Za-z_$][A-Za-z0-9_$.]*$")
_GUARDIAN_CODE_IN_TEXT = re.compile(r"guardian_[a-z0-9_]+", re.IGNORECASE)
_LANE_STATUSES = {"allowed", "invalid", "unsupported", "not_assessed"}
_FINDING_KINDS = {"source_ignore", "diagnostic_disable", "guardian_bypass_marker"}


def _exact_object(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise FlutterAdapterIntegrityError(f"{field} has unknown or missing fields.")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FlutterAdapterIntegrityError(f"{field} must be a non-empty string.")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise FlutterAdapterIntegrityError(f"{field} must be an integer >= {minimum}.")
    return value


def _safe_relative_path(value: Any, field: str) -> str:
    path = _string(value, field).replace("\\", "/")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path.startswith("./"):
        raise FlutterAdapterIntegrityError(f"{field} must be a normalized project-relative path.")
    return pure.as_posix()


def _identity_list(value: Any, field: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise FlutterAdapterIntegrityError(f"{field} must be a canonical identity array.")
    if any(not isinstance(item, str) or not _CODE_IDENTITY.fullmatch(item) for item in value):
        raise FlutterAdapterIntegrityError(f"{field} contains an invalid code identity.")
    if value != sorted(set(value)):
        raise FlutterAdapterIntegrityError(f"{field} must be unique and sorted.")
    return tuple(value)


def _validate_run_pin(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FlutterAdapterIntegrityError("Flutter normalization requires one verified run pin.")
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        _string(value.get(field), f"run pin {field}")
    if value.get("schemaVersion") != 1 or not isinstance(value.get("sourceCut"), dict):
        raise FlutterAdapterIntegrityError("Run pin schema or sourceCut is invalid.")
    for field in ("snapshotId", "policyDigest"):
        if not _HEX_64.fullmatch(str(value[field])):
            raise FlutterAdapterIntegrityError(f"Run pin {field} must be a lowercase SHA-256 digest.")
    return copy.deepcopy(value)


def _validate_config(value: Any, pin: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FlutterAdapterIntegrityError("Flutter adapter config must be an object.")
    schema_version = value.get("schemaVersion")
    expected_keys = (
        _CONFIG_V1_KEYS
        if schema_version == 1
        else _CONFIG_V2_KEYS
        if schema_version == 2
        else set()
    )
    config = _exact_object(value, expected_keys, "Flutter adapter config")
    if config.get("adapter") != "flutter" or config.get("adapterVersion") != "0.1.0":
        raise FlutterAdapterIntegrityError("Flutter adapter config schema or version is unsupported.")
    profile_id = config.get("profileId")
    if not isinstance(profile_id, str) or not _PROFILE_ID.fullmatch(profile_id):
        raise FlutterAdapterIntegrityError("Flutter adapter config profileId is invalid.")
    for field in ("policyDigest", "snapshotId", "sourceCutDigest", "configDigest"):
        if not isinstance(config.get(field), str) or not _HEX_64.fullmatch(config[field]):
            raise FlutterAdapterIntegrityError(f"Flutter adapter config {field} must be a lowercase SHA-256 digest.")
    expected = {
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
    }
    for field, exact in expected.items():
        if config.get(field) != exact:
            raise FlutterAdapterIntegrityError(f"Flutter adapter config {field} differs from the run pin.")
    unsigned = copy.deepcopy(config)
    claimed_digest = unsigned.pop("configDigest")
    if sha256_digest(unsigned) != claimed_digest:
        raise FlutterAdapterIntegrityError("Flutter adapter configDigest does not match canonical config content.")

    identities = config.get("approvedIdentities")
    if not isinstance(identities, dict) or set(identities) != _IDENTITY_CATEGORIES:
        raise FlutterAdapterIntegrityError("Flutter approvedIdentities must contain every exact category.")
    normalized = {
        category: _identity_list(identities[category], f"approvedIdentities.{category}", allow_empty=True)
        for category in sorted(_IDENTITY_CATEGORIES)
    }
    variants = config.get("componentVariants")
    if not isinstance(variants, dict):
        raise FlutterAdapterIntegrityError("Flutter componentVariants must be an object.")
    for constructor, properties in variants.items():
        if not isinstance(constructor, str) or not _CODE_IDENTITY.fullmatch(constructor) or constructor not in normalized["widgets"]:
            raise FlutterAdapterIntegrityError("A componentVariants key is not an approved widget identity.")
        if not isinstance(properties, dict) or not properties:
            raise FlutterAdapterIntegrityError("Component variant properties must be a non-empty object.")
        for property_name, allowed in properties.items():
            _string(property_name, "component variant property")
            _identity_list(allowed, f"componentVariants.{constructor}.{property_name}", allow_empty=False)
    try:
        approved_packages = validate_approved_package_bindings(
            config.get("approvedPackages"),
            identities,
            variants,
        )
        validate_required_package_bindings(
            config.get("requiredPackages"), approved_packages=approved_packages
        )
        toolchain = validate_toolchain_binding(config.get("toolchain"))
        if toolchain["platformId"] != current_platform_id():
            raise FlutterToolchainIntegrityError(
                "Flutter adapter toolchain does not match the current host platform."
            )
    except (FlutterPackageProvenanceError, FlutterToolchainIntegrityError) as error:
        raise FlutterAdapterIntegrityError(str(error)) from error
    if schema_version == 2:
        try:
            from .flutter_config import FlutterConfigError, _validate_config_document

            _validate_config_document(config)
        except FlutterConfigError as error:
            raise FlutterAdapterIntegrityError(
                f"Flutter usage-rule configuration is invalid: {error}"
            ) from error
    return copy.deepcopy(config)


def _validate_binding(value: Any, config: dict[str, Any], pin: dict[str, Any]) -> dict[str, str]:
    binding = _exact_object(value, _BINDING_KEYS, "Flutter adapter binding")
    expected = {
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "configDigest": config["configDigest"],
    }
    for field, exact in expected.items():
        if binding.get(field) != exact or config.get(field) != exact:
            raise FlutterAdapterIntegrityError(f"Flutter adapter binding {field} is not exact across config and run pin.")
    return expected


def _canonical_code(value: Any) -> str:
    code = _string(value, "diagnostic.code").lower()
    if "/" in code:
        namespace, code = code.rsplit("/", 1)
        if namespace != "design_system_guardian_flutter":
            raise FlutterAdapterIntegrityError("Diagnostic plugin namespace is not Guardian Flutter.")
    if code == "guardian_invalid_config_binding":
        raise FlutterAdapterIntegrityError("Flutter analyzer reported invalid configuration binding.")
    if code not in _CODE_CATEGORIES:
        raise FlutterAdapterIntegrityError(f"Unknown Guardian Flutter diagnostic code: {code}.")
    return code


def _raw_diagnostic(value: Any) -> dict[str, Any]:
    diagnostic = _exact_object(value, _DIAGNOSTIC_KEYS, "Flutter diagnostic")
    if diagnostic.get("severity") not in {"INFO", "WARNING", "ERROR"}:
        raise FlutterAdapterIntegrityError("Flutter diagnostic severity is invalid.")
    return {
        "severity": diagnostic["severity"],
        "code": _canonical_code(diagnostic.get("code")),
        "path": _safe_relative_path(diagnostic.get("path"), "diagnostic.path"),
        "line": _integer(diagnostic.get("line"), "diagnostic.line", minimum=1),
        "column": _integer(diagnostic.get("column"), "diagnostic.column", minimum=1),
        "length": _integer(diagnostic.get("length"), "diagnostic.length"),
        "message": _string(diagnostic.get("message"), "diagnostic.message"),
    }


def _validate_scan(value: Any) -> dict[str, Any]:
    scan = _exact_object(value, _SCAN_KEYS, "Flutter suppression scan")
    if scan.get("schemaVersion") != 1 or scan.get("method") != "conservative_text_scan" or scan.get("astProof") is not False:
        raise FlutterAdapterIntegrityError("Flutter suppression scan contract is invalid.")
    if not isinstance(scan.get("findings"), list):
        raise FlutterAdapterIntegrityError("Flutter suppression findings must be an array.")
    findings: list[dict[str, Any]] = []
    for item in scan["findings"]:
        finding = _exact_object(item, _FINDING_KEYS, "Suppression finding")
        if finding.get("kind") not in _FINDING_KINDS:
            raise FlutterAdapterIntegrityError("Suppression finding kind is invalid.")
        findings.append({
            "path": _safe_relative_path(finding.get("path"), "suppression.path"),
            "line": _integer(finding.get("line"), "suppression.line", minimum=1),
            "text": _string(finding.get("text"), "suppression.text"),
            "kind": finding["kind"],
        })
    expected = sorted(findings, key=lambda item: (item["path"], item["line"], item["text"]))
    if findings != expected:
        raise FlutterAdapterIntegrityError("Suppression findings must be in deterministic order.")
    return {"schemaVersion": 1, "method": "conservative_text_scan", "astProof": False, "findings": findings}


def _core_diagnostic(raw: Mapping[str, Any], category: str, binding: Mapping[str, str]) -> dict[str, Any]:
    evidence = {
        "adapter": "flutter",
        "proofMethod": "dart_analyzer_ast",
        "code": raw["code"],
        "path": raw["path"],
        "line": raw["line"],
        "column": raw["column"],
        "length": raw["length"],
        "binding": dict(binding),
    }
    identity = {"category": category, "message": raw["message"], "evidence": evidence}
    return {
        "diagnosticId": "flutter-" + sha256_digest(identity)[:24],
        "category": category,
        "kind": "violation",
        "message": raw["message"],
        "evidence": evidence,
    }


def _suppression_categories(text: str) -> tuple[str, ...]:
    categories: set[str] = set()
    for match in _GUARDIAN_CODE_IN_TEXT.findall(text):
        categories.update(_CODE_CATEGORIES.get(match.lower(), ()))
    return tuple(category for category in AUDIT_CATEGORIES if category in categories) or AUDIT_CATEGORIES


def _suppression_diagnostics(scan: Mapping[str, Any], binding: Mapping[str, str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for finding in scan["findings"]:
        for category in _suppression_categories(finding["text"]):
            evidence = {
                "adapter": "flutter",
                "proofMethod": "conservative_text_scan",
                "astProof": False,
                "path": finding["path"],
                "line": finding["line"],
                "kind": finding["kind"],
                "text": finding["text"],
                "binding": dict(binding),
            }
            identity = {"category": category, "evidence": evidence}
            output.append({
                "diagnosticId": "flutter-suppression-" + sha256_digest(identity)[:24],
                "category": category,
                "kind": "violation",
                "message": "Attempted suppression of Design System Guardian enforcement.",
                "evidence": evidence,
            })
    return output


def normalize_flutter_adapter_result(
    value: Any,
    *,
    adapter_config: dict[str, Any],
    run_pin: dict[str, Any],
) -> dict[str, Any]:
    """Validate the shipped Flutter result and project audit.py's exact contract."""

    raw = _exact_object(value, _TOP_KEYS, "Flutter adapter result")
    if raw.get("schemaVersion") != 1:
        raise FlutterAdapterIntegrityError("Flutter adapter schemaVersion must be exactly 1.")
    adapter = _string(raw.get("adapter"), "adapter")
    adapter_version = _string(raw.get("adapterVersion"), "adapterVersion")
    if raw.get("status") not in _LANE_STATUSES:
        raise FlutterAdapterIntegrityError("Flutter adapter status is invalid.")
    if not isinstance(raw.get("productionReady"), bool):
        raise FlutterAdapterIntegrityError("Flutter adapter productionReady must be boolean.")

    pin = _validate_run_pin(run_pin)
    config = _validate_config(adapter_config, pin)
    binding = _validate_binding(raw.get("binding"), config, pin)

    analysis = _exact_object(raw.get("analysis"), _ANALYSIS_KEYS, "Flutter analysis")
    if analysis.get("method") != "dart_analyzer_ast" or not isinstance(analysis.get("complete"), bool):
        raise FlutterAdapterIntegrityError("Flutter analysis must be explicit Dart analyzer AST evidence.")
    assessed_files = _integer(analysis.get("assessedFiles"), "analysis.assessedFiles")
    total_files = _integer(analysis.get("totalFiles"), "analysis.totalFiles")
    if total_files < 1:
        raise FlutterAdapterIntegrityError("Flutter analysis must assess at least one relevant file.")
    if assessed_files > total_files:
        raise FlutterAdapterIntegrityError("Flutter assessedFiles cannot exceed totalFiles.")

    coverage = _exact_object(raw.get("coverage"), set(AUDIT_CATEGORIES), "Flutter coverage")
    lane_statuses: dict[str, str] = {}
    lane_counts: dict[str, int] = {}
    for category in AUDIT_CATEGORIES:
        lane = _exact_object(coverage[category], _LANE_KEYS, f"coverage.{category}")
        status = lane.get("status")
        if status not in _LANE_STATUSES or lane.get("method") != "dart_analyzer_ast":
            raise FlutterAdapterIntegrityError(f"Flutter coverage lane {category} is invalid.")
        lane_statuses[category] = status
        lane_counts[category] = _integer(lane.get("diagnosticCount"), f"coverage.{category}.diagnosticCount")

    if not isinstance(raw.get("diagnostics"), list):
        raise FlutterAdapterIntegrityError("Flutter diagnostics must be an array.")
    diagnostics = [_raw_diagnostic(item) for item in raw["diagnostics"]]
    expected_order = sorted(diagnostics, key=lambda item: (item["path"], item["line"], item["column"], item["code"], item["message"]))
    if diagnostics != expected_order:
        raise FlutterAdapterIntegrityError("Flutter diagnostics must be in deterministic order.")
    scan = _validate_scan(raw.get("suppressionScan"))

    core_diagnostics: list[dict[str, Any]] = []
    diagnostic_counts = {category: 0 for category in AUDIT_CATEGORIES}
    for diagnostic in diagnostics:
        for category in _CODE_CATEGORIES[diagnostic["code"]]:
            diagnostic_counts[category] += 1
            core_diagnostics.append(_core_diagnostic(diagnostic, category, binding))
    core_diagnostics.extend(_suppression_diagnostics(scan, binding))
    core_diagnostics = sorted(core_diagnostics, key=canonical_json_bytes)
    identifiers = [item["diagnosticId"] for item in core_diagnostics]
    if len(identifiers) != len(set(identifiers)):
        raise FlutterAdapterIntegrityError("Normalized Flutter diagnostic IDs collide.")
    for category in AUDIT_CATEGORIES:
        if lane_counts[category] != diagnostic_counts[category]:
            raise FlutterAdapterIntegrityError(f"Flutter coverage count for {category} differs from AST evidence.")

    if raw["status"] == "invalid" or any(status == "invalid" for status in lane_statuses.values()):
        raise FlutterAdapterIntegrityError("Invalid Flutter adapter evidence cannot enter the audit lane.")
    unsupported_adapter = adapter != "flutter" or adapter_version != "0.1.0"
    supported = not unsupported_adapter and raw["status"] != "unsupported" and not any(
        status == "unsupported" for status in lane_statuses.values()
    )
    complete_analysis = analysis["complete"] is True and assessed_files == total_files
    all_coverage_allowed = all(status == "allowed" for status in lane_statuses.values())
    expected_status = "unsupported" if not supported else "allowed" if complete_analysis and all_coverage_allowed else "not_assessed"
    if raw["status"] != expected_status:
        raise FlutterAdapterIntegrityError("Flutter result status differs from exact analysis and coverage evidence.")
    expected_ready = expected_status == "allowed" and not core_diagnostics
    if raw["productionReady"] is not expected_ready:
        raise FlutterAdapterIntegrityError("Flutter productionReady differs from exact analyzer evidence.")

    internal_categories: dict[str, dict[str, Any]] = {}
    for category in AUDIT_CATEGORIES:
        raw_status = lane_statuses[category]
        if not complete_analysis:
            status = "not_assessed"
        elif config["schemaVersion"] == 1 and raw["status"] == "not_assessed":
            status = "not_assessed"
        elif raw_status == "unsupported":
            status = "unsupported"
        elif raw_status == "not_assessed":
            status = "not_assessed"
        else:
            status = "allowed"
        internal_categories[category] = {
            "status": status,
            "assessedItems": assessed_files if status == "allowed" else 0,
            "totalItems": total_files,
        }

    return {
        "schemaVersion": 1,
        "adapter": "flutter" if not unsupported_adapter else f"{adapter}@{adapter_version}",
        "supported": supported,
        "configDigest": config["configDigest"],
        "sourceCut": copy.deepcopy(pin["sourceCut"]),
        "assessedFiles": assessed_files,
        "totalFiles": total_files,
        "categories": internal_categories,
        "diagnostics": core_diagnostics,
    }

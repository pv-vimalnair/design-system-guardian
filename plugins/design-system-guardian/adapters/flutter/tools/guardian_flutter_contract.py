#!/usr/bin/env python3
"""Strict Flutter adapter contracts for Design System Guardian.

This tool never calls a text scan AST evidence. `normalize` accepts only a
schema-v1 Flutter result produced from Dart analyzer AST rules, verifies its
exact binding against the generated adapter config and sealed run pin, and
projects the exact evidence shape consumed by guardian_core.audit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


_AST_ANALYSIS_EVIDENCE = {"method": "dart_analyzer_ast"}
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

_RESULT_KEYS = {
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
_BINDING_KEYS = {
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "configDigest",
}
_ANALYSIS_KEYS = {"method", "complete", "assessedFiles", "totalFiles"}
_COVERAGE_LANE_KEYS = {"status", "method", "diagnosticCount"}
_DIAGNOSTIC_KEYS = {"severity", "code", "path", "line", "column", "length", "message"}
_SUPPRESSION_KEYS = {"schemaVersion", "method", "astProof", "findings"}
_SUPPRESSION_FINDING_KEYS = {"path", "line", "text", "kind"}
_CONFIG_V1_KEYS = {
    "schemaVersion",
    "adapter",
    "adapterVersion",
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "configDigest",
    "approvedPackages",
    "toolchain",
    "requiredPackages",
    "approvedIdentities",
    "componentVariants",
}
_CONFIG_V2_KEYS = _CONFIG_V1_KEYS | {
    "ruleSnapshotId",
    "rulesDigest",
    "activeUsageRules",
    "usageRuleCoverage",
}
_IDENTITY_CATEGORIES = {
    "colors",
    "textStyles",
    "icons",
    "dimensions",
    "effects",
    "motion",
    "widgets",
}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CODE_IDENTITY = re.compile(r"^(?:dart|package):[^#\s]+#[A-Za-z_$][A-Za-z0-9_$.]*$")
_PACKAGE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_REPOSITORY_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RULE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")

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

_SCAN_EXCLUDED_DIRECTORIES = {
    ".dart_tool",
    ".git",
    ".idea",
    ".pub-cache",
    "build",
    "coverage",
}
_SOURCE_IGNORE = re.compile(
    r"(?:ignore(?:_for_file)?\s*:).*?(?:design_system_guardian_flutter/|guardian_)",
    re.IGNORECASE,
)
_DIAGNOSTIC_DISABLE = re.compile(
    r"(?:guardian_[a-z0-9_]+|design_system_guardian_flutter)\s*:\s*(?:false|ignore)\b",
    re.IGNORECASE,
)
_BYPASS_MARKER = re.compile(
    r"guardian(?:\s*:\s*ignore|-ignore|_bypass)",
    re.IGNORECASE,
)
_GUARDIAN_CODE_IN_TEXT = re.compile(r"guardian_[a-z0-9_]+", re.IGNORECASE)


class ContractError(ValueError):
    """Input cannot be trusted or represented by the strict contract."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ContractError(f"{label} contains non-finite JSON number {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read canonical {label}: {error}") from error
    if not isinstance(payload, dict):
        raise ContractError(f"{label} root must be an object")
    return payload


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ContractError(f"{label} has unknown or missing fields")


def _plain_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    path = _nonempty_string(value, label).replace("\\", "/")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path.startswith("./"):
        raise ContractError(f"{label} must be a normalized project-relative path")
    return pure.as_posix()


def _validate_identity_list(value: Any, label: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ContractError(f"{label} must be an {'optionally empty' if allow_empty else 'non-empty'} array")
    if any(not isinstance(item, str) or not _CODE_IDENTITY.fullmatch(item) for item in value):
        raise ContractError(f"{label} contains a non-canonical code identity")
    if value != sorted(set(value)):
        raise ContractError(f"{label} must be unique and lexicographically sorted")
    return tuple(value)


def _identity_package(value: str, label: str) -> str:
    if not value.startswith("package:") or value.startswith("package:flutter/") or value.startswith("package:design_system_guardian_flutter/"):
        raise ContractError(f"{label} must use an approved non-framework package identity")
    uri = value[len("package:") : value.index("#")]
    if any(marker in uri for marker in ("\\", "%", "?", ":")) or "/" not in uri:
        raise ContractError(f"{label} has package/path impersonation syntax")
    package_name, path = uri.split("/", 1)
    pure = PurePosixPath(path)
    if (
        not _PACKAGE_NAME.fullmatch(package_name)
        or not path
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != path
    ):
        raise ContractError(f"{label} has a non-canonical package identity")
    return package_name


def _validate_usage_rule_config(
    config: Mapping[str, Any],
    approved_widgets: tuple[str, ...],
) -> None:
    if (
        config.get("ruleSnapshotId") != config.get("snapshotId")
        or not isinstance(config.get("ruleSnapshotId"), str)
        or not _DIGEST.fullmatch(config["ruleSnapshotId"])
        or not isinstance(config.get("rulesDigest"), str)
        or not _DIGEST.fullmatch(config["rulesDigest"])
    ):
        raise ContractError("v2 rule snapshot bindings are invalid")
    active = config.get("activeUsageRules")
    if not isinstance(active, list):
        raise ContractError("activeUsageRules must be an array")
    active_ids: list[str] = []
    for item in active:
        if not isinstance(item, dict):
            raise ContractError("activeUsageRules contains a malformed rule")
        predicate = item.get("predicate")
        expected = {"ruleId", "predicate", "scope", "constructorIdentities"}
        if predicate == "max_instances_per_scope":
            expected.add("max")
        if (
            set(item) != expected
            or predicate
            not in {"forbidden_identity_in_scope", "max_instances_per_scope"}
            or item.get("scope") != "compilation_unit"
        ):
            raise ContractError("activeUsageRules contains an unsupported predicate")
        rule_id = item.get("ruleId")
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise ContractError("activeUsageRules contains an invalid ruleId")
        constructors = _validate_identity_list(
            item.get("constructorIdentities"),
            f"activeUsageRules.{rule_id}.constructorIdentities",
            allow_empty=False,
        )
        if any(identity not in approved_widgets for identity in constructors):
            raise ContractError("activeUsageRules constructor is not an approved widget")
        maximum = item.get("max")
        if predicate == "max_instances_per_scope" and (
            isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0
        ):
            raise ContractError("activeUsageRules maximum is invalid")
        active_ids.append(rule_id)
    if active_ids != sorted(set(active_ids)):
        raise ContractError("activeUsageRules must be sorted and unique")
    coverage = config.get("usageRuleCoverage")
    if not isinstance(coverage, dict) or set(coverage) != {
        "status",
        "activeRuleIds",
        "inactive",
        "informativeRuleIds",
    }:
        raise ContractError("usageRuleCoverage has unknown or missing fields")
    if coverage.get("activeRuleIds") != active_ids:
        raise ContractError("usageRuleCoverage activeRuleIds differs from compiled rules")
    informative = coverage.get("informativeRuleIds")
    if (
        not isinstance(informative, list)
        or any(not isinstance(item, str) or not _RULE_ID.fullmatch(item) for item in informative)
        or informative != sorted(set(informative))
    ):
        raise ContractError("usageRuleCoverage informativeRuleIds is invalid")
    inactive = coverage.get("inactive")
    if not isinstance(inactive, list):
        raise ContractError("usageRuleCoverage inactive must be an array")
    inactive_ids: list[str] = []
    for item in inactive:
        if (
            not isinstance(item, dict)
            or set(item) != {"ruleId", "reasonCode"}
            or not isinstance(item.get("ruleId"), str)
            or not _RULE_ID.fullmatch(item["ruleId"])
            or item.get("reasonCode")
            not in {
                "identity_not_mapped",
                "unsupported_predicate_scope",
                "unsupported_rule_class",
            }
        ):
            raise ContractError("usageRuleCoverage inactive metadata is invalid")
        inactive_ids.append(item["ruleId"])
    if inactive_ids != sorted(set(inactive_ids)):
        raise ContractError("usageRuleCoverage inactive rules must be sorted and unique")
    all_ids = active_ids + inactive_ids + informative
    if len(all_ids) != len(set(all_ids)):
        raise ContractError("usageRuleCoverage rule classes overlap")
    expected_status = "incomplete" if inactive else "complete"
    if coverage.get("status") != expected_status:
        raise ContractError("usageRuleCoverage status differs from inactive evidence")


def validate_adapter_config(config: Mapping[str, Any]) -> dict[str, Any]:
    schema_version = config.get("schemaVersion")
    expected_keys = (
        _CONFIG_V1_KEYS
        if schema_version == 1
        else _CONFIG_V2_KEYS
        if schema_version == 2
        else set()
    )
    _require_exact_keys(config, expected_keys, "Flutter adapter config")
    if config.get("adapter") != "flutter" or config.get("adapterVersion") != "0.1.0":
        raise ContractError("Flutter adapter config schema or version is unsupported")
    profile_id = config.get("profileId")
    if not isinstance(profile_id, str) or not _PROFILE_ID.fullmatch(profile_id):
        raise ContractError("config profileId is invalid")
    for field in ("policyDigest", "sourceCutDigest", "configDigest"):
        if not isinstance(config.get(field), str) or not _DIGEST.fullmatch(config[field]):
            raise ContractError(f"config {field} must be a lowercase SHA-256 digest")
    _nonempty_string(config.get("snapshotId"), "config snapshotId")
    unsigned = dict(config)
    claimed_digest = unsigned.pop("configDigest")
    if _digest(unsigned) != claimed_digest:
        raise ContractError("configDigest does not match canonical adapter config content")

    toolchain = config.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {"platformId", "dartSdk"}:
        raise ContractError("toolchain must be one exact platform-bound Dart SDK")
    platform_id = toolchain.get("platformId")
    supported_platforms = {"windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64"}
    dart_sdk = toolchain.get("dartSdk")
    if platform_id not in supported_platforms or not isinstance(dart_sdk, dict) or set(dart_sdk) != {"contentDigest", "executableRelativePath"} or not isinstance(dart_sdk.get("contentDigest"), str) or not _DIGEST.fullmatch(dart_sdk["contentDigest"]):
        raise ContractError("toolchain Dart SDK binding is malformed")
    expected_executable = "bin/dart.exe" if str(platform_id).startswith("windows-") else "bin/dart"
    if dart_sdk.get("executableRelativePath") != expected_executable:
        raise ContractError("toolchain executable identity is not exact for its platform")

    required_packages = config.get("requiredPackages")
    if not isinstance(required_packages, dict) or "flutter" not in required_packages:
        raise ContractError("requiredPackages must contain exact flutter authority")
    for package_name, package in required_packages.items():
        if not isinstance(package_name, str) or not _PACKAGE_NAME.fullmatch(package_name) or package_name == "design_system_guardian_flutter" or not isinstance(package, dict) or set(package) != {"contentDigest", "repositoryCommit"} or not isinstance(package.get("contentDigest"), str) or not _DIGEST.fullmatch(package["contentDigest"]) or not isinstance(package.get("repositoryCommit"), str) or not _REPOSITORY_COMMIT.fullmatch(package["repositoryCommit"]):
            raise ContractError(f"requiredPackages.{package_name} is malformed or forbidden")

    identities = config.get("approvedIdentities")
    if not isinstance(identities, dict) or set(identities) != _IDENTITY_CATEGORIES:
        raise ContractError("approvedIdentities must contain every exact Flutter category")
    normalized_identities = {category: _validate_identity_list(identities[category], f"approvedIdentities.{category}", allow_empty=True) for category in sorted(_IDENTITY_CATEGORIES)}
    variants = config.get("componentVariants")
    if not isinstance(variants, dict):
        raise ContractError("componentVariants must be an object")
    for constructor, properties in variants.items():
        if not isinstance(constructor, str) or not _CODE_IDENTITY.fullmatch(constructor) or constructor not in normalized_identities["widgets"]:
            raise ContractError("componentVariants key must be an approved widget identity")
        if not isinstance(properties, dict) or not properties:
            raise ContractError("componentVariants properties must be a non-empty object")
        for property_name, allowed in properties.items():
            _nonempty_string(property_name, "component variant property")
            _validate_identity_list(allowed, f"componentVariants.{constructor}.{property_name}", allow_empty=False)
    packages = config.get("approvedPackages")
    if not isinstance(packages, dict):
        raise ContractError("approvedPackages must be an object")
    normalized_packages = {}
    for package_name, package in packages.items():
        if not isinstance(package_name, str) or not _PACKAGE_NAME.fullmatch(package_name) or package_name in {"flutter", "design_system_guardian_flutter"} or not isinstance(package, dict) or set(package) != {"contentDigest", "repositoryCommit"} or not isinstance(package.get("contentDigest"), str) or not _DIGEST.fullmatch(package["contentDigest"]) or not isinstance(package.get("repositoryCommit"), str) or not _REPOSITORY_COMMIT.fullmatch(package["repositoryCommit"]):
            raise ContractError(f"approvedPackages.{package_name} is malformed or forbidden")
        normalized_packages[package_name] = package
    if set(required_packages) & set(normalized_packages):
        raise ContractError("required semantic packages cannot become approved visual packages")
    used_packages = set()
    for category, values in normalized_identities.items():
        for index, identity in enumerate(values):
            package_name = _identity_package(identity, f"approvedIdentities.{category}[{index}]")
            if package_name not in normalized_packages:
                raise ContractError("approved identity has no exact approved package")
            used_packages.add(package_name)
    for constructor, properties in variants.items():
        widget_package = _identity_package(constructor, "componentVariants widget")
        for property_name, values in properties.items():
            for index, identity in enumerate(values):
                if _identity_package(identity, f"componentVariants.{constructor}.{property_name}[{index}]") != widget_package:
                    raise ContractError("component variant impersonates another package")
        used_packages.add(widget_package)
    if used_packages != set(normalized_packages):
        raise ContractError("approvedPackages must exactly bind all approved identities")
    if schema_version == 2:
        _validate_usage_rule_config(config, normalized_identities["widgets"])
    return json.loads(_canonical_json_bytes(config))

def _validate_run_pin(run_pin: Mapping[str, Any]) -> dict[str, Any]:
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        _nonempty_string(run_pin.get(field), f"run pin {field}")
    if run_pin.get("schemaVersion") != 1 or not isinstance(run_pin.get("sourceCut"), dict):
        raise ContractError("run pin schema or sourceCut is invalid")
    if not _DIGEST.fullmatch(str(run_pin["snapshotId"])):
        raise ContractError("run pin snapshotId must be a lowercase SHA-256 digest")
    if not _DIGEST.fullmatch(str(run_pin["policyDigest"])):
        raise ContractError("run pin policyDigest must be a lowercase SHA-256 digest")
    return json.loads(_canonical_json_bytes(run_pin))


def _validate_binding(
    binding: Any,
    config: Mapping[str, Any],
    run_pin: Mapping[str, Any],
) -> dict[str, str]:
    if not isinstance(binding, dict):
        raise ContractError("Flutter result binding must be an object")
    _require_exact_keys(binding, _BINDING_KEYS, "Flutter result binding")
    expected = {
        "profileId": run_pin["profileId"],
        "policyDigest": run_pin["policyDigest"],
        "snapshotId": run_pin["snapshotId"],
        "sourceCutDigest": _digest(run_pin["sourceCut"]),
        "configDigest": config["configDigest"],
    }
    for field, value in expected.items():
        if binding.get(field) != value or config.get(field) != value:
            raise ContractError(f"{field} is not exactly bound across result, config, and run pin")
    return dict(expected)


def _canonical_code(value: Any) -> str:
    code = _nonempty_string(value, "diagnostic code").lower()
    if "/" in code:
        plugin_name, code = code.rsplit("/", 1)
        if plugin_name != "design_system_guardian_flutter":
            raise ContractError("diagnostic plugin namespace is not Design System Guardian Flutter")
    return code


def _validate_raw_diagnostic(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("Flutter diagnostic must be an object")
    _require_exact_keys(value, _DIAGNOSTIC_KEYS, "Flutter diagnostic")
    severity = value.get("severity")
    if severity not in {"INFO", "WARNING", "ERROR"}:
        raise ContractError("diagnostic severity is invalid")
    code = _canonical_code(value.get("code"))
    if code == "guardian_invalid_config_binding":
        raise ContractError("analyzer reported an invalid Guardian config binding")
    if code.startswith("guardian_") and code not in _CODE_CATEGORIES:
        raise ContractError(f"unknown Guardian diagnostic code: {code}")
    if not code.startswith("guardian_"):
        raise ContractError("Flutter adapter result may contain only Guardian diagnostics")
    return {
        "severity": severity,
        "code": code,
        "path": _safe_relative_path(value.get("path"), "diagnostic path"),
        "line": _plain_nonnegative_int(value.get("line"), "diagnostic line"),
        "column": _plain_nonnegative_int(value.get("column"), "diagnostic column"),
        "length": _plain_nonnegative_int(value.get("length"), "diagnostic length"),
        "message": _nonempty_string(value.get("message"), "diagnostic message"),
    }


def _validate_suppression_scan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("suppressionScan must be an object")
    _require_exact_keys(value, _SUPPRESSION_KEYS, "suppressionScan")
    if (
        value.get("schemaVersion") != 1
        or value.get("method") != "conservative_text_scan"
        or value.get("astProof") is not False
    ):
        raise ContractError("suppression scan must explicitly be conservative text evidence, not AST proof")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise ContractError("suppression findings must be an array")
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ContractError("suppression finding must be an object")
        _require_exact_keys(finding, _SUPPRESSION_FINDING_KEYS, "suppression finding")
        kind = finding.get("kind")
        if kind not in {"source_ignore", "diagnostic_disable", "guardian_bypass_marker"}:
            raise ContractError("suppression finding kind is invalid")
        normalized.append(
            {
                "path": _safe_relative_path(finding.get("path"), "suppression path"),
                "line": _plain_nonnegative_int(finding.get("line"), "suppression line"),
                "text": _nonempty_string(finding.get("text"), "suppression text"),
                "kind": kind,
            }
        )
    ordered = sorted(normalized, key=lambda item: (item["path"], item["line"], item["text"]))
    if normalized != ordered:
        raise ContractError("suppression findings must be in deterministic order")
    return {
        "schemaVersion": 1,
        "method": "conservative_text_scan",
        "astProof": False,
        "findings": ordered,
    }


def _core_diagnostic(
    raw: Mapping[str, Any],
    category: str,
    binding: Mapping[str, str],
) -> dict[str, Any]:
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
    identity = {
        "category": category,
        "message": raw["message"],
        "evidence": evidence,
    }
    return {
        "diagnosticId": f"flutter-{_digest(identity)[:24]}",
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


def _core_suppression_diagnostics(
    scan: Mapping[str, Any],
    binding: Mapping[str, str],
) -> list[dict[str, Any]]:
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
            output.append(
                {
                    "diagnosticId": f"flutter-suppression-{_digest(identity)[:24]}",
                    "category": category,
                    "kind": "violation",
                    "message": "Attempted suppression of Design System Guardian enforcement.",
                    "evidence": evidence,
                }
            )
    return output


def normalize_flutter_result_to_core(
    result: Mapping[str, Any],
    config: Mapping[str, Any],
    run_pin: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one Flutter result and project exact guardian_core.audit evidence."""

    if not isinstance(result, dict):
        raise ContractError("Flutter result must be an object")
    _require_exact_keys(result, _RESULT_KEYS, "Flutter result")
    if (
        result.get("schemaVersion") != 1
        or result.get("adapter") != "flutter"
        or result.get("adapterVersion") != "0.1.0"
    ):
        raise ContractError("Flutter result schema or adapter version is unsupported")
    if result.get("status") not in {"allowed", "invalid", "unsupported", "not_assessed"}:
        raise ContractError("Flutter result status is invalid")

    normalized_config = validate_adapter_config(config)
    normalized_pin = _validate_run_pin(run_pin)
    binding = _validate_binding(result.get("binding"), normalized_config, normalized_pin)

    analysis = result.get("analysis")
    if not isinstance(analysis, dict):
        raise ContractError("Flutter result analysis must be an object")
    _require_exact_keys(analysis, _ANALYSIS_KEYS, "Flutter result analysis")
    if (
        analysis.get("method") != _AST_ANALYSIS_EVIDENCE["method"]
        or not isinstance(analysis.get("complete"), bool)
    ):
        raise ContractError("Flutter result analysis must explicitly use Dart analyzer AST evidence")
    assessed_files = _plain_nonnegative_int(analysis.get("assessedFiles"), "assessedFiles")
    total_files = _plain_nonnegative_int(analysis.get("totalFiles"), "totalFiles")
    if total_files < 1:
        raise ContractError("Flutter analysis must assess at least one relevant file")
    if assessed_files > total_files:
        raise ContractError("assessedFiles cannot exceed totalFiles")

    coverage = result.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != set(AUDIT_CATEGORIES):
        raise ContractError("Flutter result coverage must report every exact category")
    normalized_coverage: dict[str, dict[str, Any]] = {}
    for category in AUDIT_CATEGORIES:
        lane = coverage[category]
        if not isinstance(lane, dict):
            raise ContractError(f"coverage.{category} must be an object")
        _require_exact_keys(lane, _COVERAGE_LANE_KEYS, f"coverage.{category}")
        status = lane.get("status")
        if status not in {"allowed", "invalid", "unsupported", "not_assessed"}:
            raise ContractError(f"coverage.{category}.status is invalid")
        if lane.get("method") != _AST_ANALYSIS_EVIDENCE["method"]:
            raise ContractError(f"coverage.{category} is not Dart analyzer AST evidence")
        normalized_coverage[category] = {
            "status": status,
            "diagnosticCount": _plain_nonnegative_int(
                lane.get("diagnosticCount"), f"coverage.{category}.diagnosticCount"
            ),
        }

    diagnostics_value = result.get("diagnostics")
    if not isinstance(diagnostics_value, list):
        raise ContractError("Flutter result diagnostics must be an array")
    raw_diagnostics = [_validate_raw_diagnostic(item) for item in diagnostics_value]
    raw_order = sorted(
        raw_diagnostics,
        key=lambda item: (
            item["path"],
            item["line"],
            item["column"],
            item["code"],
            item["message"],
        ),
    )
    if raw_diagnostics != raw_order:
        raise ContractError("Flutter diagnostics must be in deterministic order")
    suppression_scan = _validate_suppression_scan(result.get("suppressionScan"))

    core_diagnostics: list[dict[str, Any]] = []
    ast_diagnostic_counts = {category: 0 for category in AUDIT_CATEGORIES}
    for raw in raw_diagnostics:
        for category in _CODE_CATEGORIES[raw["code"]]:
            core_diagnostics.append(_core_diagnostic(raw, category, binding))
            ast_diagnostic_counts[category] += 1
    for diagnostic in _core_suppression_diagnostics(suppression_scan, binding):
        core_diagnostics.append(diagnostic)
    core_diagnostics = sorted(core_diagnostics, key=_canonical_json_bytes)
    ids = [item["diagnosticId"] for item in core_diagnostics]
    if len(ids) != len(set(ids)):
        raise ContractError("normalized diagnostic IDs collide")

    for category in AUDIT_CATEGORIES:
        if normalized_coverage[category]["diagnosticCount"] != ast_diagnostic_counts[category]:
            raise ContractError(f"coverage.{category}.diagnosticCount differs from evidence")

    complete_analysis = analysis["complete"] is True and assessed_files == total_files
    any_invalid = result["status"] == "invalid" or any(
        lane["status"] == "invalid" for lane in normalized_coverage.values()
    )
    if any_invalid:
        raise ContractError("invalid Flutter adapter evidence cannot enter the audit lane")
    supported = result["status"] != "unsupported" and not any(
        lane["status"] == "unsupported" for lane in normalized_coverage.values()
    )
    all_coverage_allowed = all(
        lane["status"] == "allowed" for lane in normalized_coverage.values()
    )
    expected_status = (
        "unsupported"
        if not supported
        else "allowed"
        if complete_analysis and all_coverage_allowed
        else "not_assessed"
    )
    if result["status"] != expected_status:
        raise ContractError("Flutter result status differs from exact analysis and coverage evidence")
    expected_production_ready = (
        expected_status == "allowed" and not core_diagnostics
    )
    if result.get("productionReady") is not expected_production_ready:
        raise ContractError("productionReady differs from exact Flutter evidence")

    core_categories: dict[str, dict[str, Any]] = {}
    for category in AUDIT_CATEGORIES:
        raw_status = normalized_coverage[category]["status"]
        core_status = "not_assessed" if not complete_analysis else raw_status if raw_status in {"allowed", "unsupported", "not_assessed"} else "not_assessed"
        assessed_items = assessed_files if core_status == "allowed" and complete_analysis else 0
        core_categories[category] = {
            "status": core_status,
            "assessedItems": assessed_items,
            "totalItems": total_files,
        }

    return {
        "schemaVersion": 1,
        "adapter": "flutter",
        "supported": supported,
        "configDigest": normalized_config["configDigest"],
        "sourceCut": normalized_pin["sourceCut"],
        "assessedFiles": assessed_files,
        "totalFiles": total_files,
        "categories": core_categories,
        "diagnostics": core_diagnostics,
    }


def scan_suppressions(project: Path) -> dict[str, Any]:
    """Conservative auxiliary scan. This output is explicitly not AST proof."""

    root = project.resolve(strict=True)
    if root.is_file():
        candidates: Iterable[Path] = (root,)
        relative_root = root.parent
    else:
        collected: list[Path] = []
        for directory, child_directories, files in os.walk(root, followlinks=False):
            child_directories[:] = sorted(
                name for name in child_directories if name not in _SCAN_EXCLUDED_DIRECTORIES
            )
            for name in sorted(files):
                path = Path(directory, name)
                if path.suffix == ".dart" or name == "analysis_options.yaml" or path.suffix in {".yml", ".yaml"}:
                    collected.append(path)
        candidates = collected
        relative_root = root

    findings: list[dict[str, Any]] = []
    for path in sorted(candidates, key=lambda item: item.as_posix()):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            raise ContractError(f"cannot scan {path}: {error}") from error
        relative = path.relative_to(relative_root).as_posix()
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if _SOURCE_IGNORE.search(line):
                kind = "source_ignore"
            elif _DIAGNOSTIC_DISABLE.search(line):
                kind = "diagnostic_disable"
            elif _BYPASS_MARKER.search(line):
                kind = "guardian_bypass_marker"
            else:
                continue
            findings.append(
                {"path": relative, "line": line_number, "text": stripped, "kind": kind}
            )
    findings = sorted(findings, key=lambda item: (item["path"], item["line"], item["text"]))
    return {
        "schemaVersion": 1,
        "method": "conservative_text_scan",
        "astProof": False,
        "findings": findings,
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical_json_bytes(value) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan-suppressions", help="run conservative non-AST suppression scan")
    scan.add_argument("--project", required=True, type=Path)
    scan.add_argument("--output", required=True, type=Path)

    normalize = commands.add_parser("normalize", help="project strict Flutter result to core audit evidence")
    normalize.add_argument("--result", required=True, type=Path)
    normalize.add_argument("--config", required=True, type=Path)
    normalize.add_argument("--run-pin", required=True, type=Path)
    normalize.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "scan-suppressions":
            result = scan_suppressions(arguments.project)
            _write_json(arguments.output, result)
            return 1 if result["findings"] else 0

        result = _load_json(arguments.result, "Flutter adapter result")
        config = _load_json(arguments.config, "Flutter adapter config")
        run_pin = _load_json(arguments.run_pin, "Guardian run pin")
        evidence = normalize_flutter_result_to_core(result, config, run_pin)
        _write_json(arguments.output, evidence)
        if not evidence["supported"] or any(
            lane["status"] != "allowed" for lane in evidence["categories"].values()
        ):
            return 4
        return 1 if evidence["diagnostics"] else 0
    except ContractError as error:
        print(json.dumps({"schemaVersion": 1, "status": "invalid", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

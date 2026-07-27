"""Generate a fail-closed Flutter analyzer allowlist from one verified run pin.

The generator never translates a display name, token value, Figma label, or
unresolved code symbol. Token Code Connect evidence is recognized only in the
``org.design-system-guardian.code-connect`` DTCG extension. Its mapping records
use the same exact five-field shape as registry Code Connect mappings.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .canonical import atomic_write_json, canonical_json_bytes, sha256_digest
from .evaluator_upgrade import (
    EVALUATOR_CAPABILITY_MATRIX,
    EVALUATOR_CONTRACT_DIGEST,
    TARGET_EVALUATOR_ID,
    EvaluatorUpgradeError,
    load_evaluator_authorization,
)
from .flutter_packages import (
    FlutterPackageProvenanceError,
    derive_approved_packages,
    validate_approved_package_bindings,
    validate_required_package_bindings,
)
from .flutter_toolchain import (
    FlutterToolchainIntegrityError,
    current_platform_id,
    select_profile_toolchain,
    validate_toolchain_binding,
)
from .policy import verify_policy_anchor
from .preflight import load_run_pin
from .paths import default_guardian_home


TOKEN_CODE_CONNECT_EXTENSION = "org.design-system-guardian.code-connect"
ADAPTER_VERSION = "0.1.0"

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
    'ruleSnapshotId',
    'rulesDigest',
    'activeUsageRules',
    'usageRuleCoverage',
}
_CONFIG_V3_KEYS = _CONFIG_V2_KEYS | {
    "runId",
    "evaluatorId",
    "evaluatorContractDigest",
    "authorizationDigest",
}

_IDENTITY_CATEGORIES = (
    "colors",
    "textStyles",
    "icons",
    "dimensions",
    "effects",
    "motion",
    "widgets",
)
_MAPPING_KEYS = {"framework", "symbol", "approved", "inferred", "sourceDigest"}
_TOKEN_TYPE_CATEGORY = {
    "color": "colors",
    "typography": "textStyles",
    "dimension": "dimensions",
    "shadow": "effects",
    "duration": "motion",
    "cubicBezier": "motion",
    "transition": "motion",
}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RULE_ID = re.compile(r'^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$')
_CODE_IDENTITY = re.compile(
    r"^(?:dart|package):[^#\s]+#[A-Za-z_$][A-Za-z0-9_$.]*$"
)


_ACTIVATED_USAGE_CAPABILITIES = [
    {'predicate': 'forbidden_identity_in_scope', 'scope': 'compilation_unit'},
    {'predicate': 'max_instances_per_scope', 'scope': 'compilation_unit'},
]
_INACTIVE_USAGE_RULE_REASONS = {
    'identity_not_mapped',
    'variant_not_mapped',
    'unsupported_predicate_scope',
    'unsupported_rule_class',
}

_USAGE_SCOPES = {"compilation_unit", "widget_class"}
_COMPANION_RELATIONS = {"child", "descendant", "sibling"}


class FlutterConfigError(ValueError):
    """Pinned evidence cannot produce an exact production-safe Flutter config."""


class FlutterAdapterUnsupportedError(FlutterConfigError):
    """The selected profile does not enable the supported Flutter adapter."""

    exit_code = 4


def _exact_code_identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_IDENTITY.fullmatch(value) is None:
        raise FlutterConfigError(f"{label} is not an exact canonical analyzer code identity.")
    if value.startswith("dart:") or value.startswith("package:flutter/"):
        raise FlutterConfigError(f"{label} selects a forbidden framework default identity.")
    if value.startswith("package:design_system_guardian_flutter/"):
        raise FlutterConfigError(f"{label} selects the diagnostic sentinel namespace.")
    return value


def _mapping_symbol(mapping: Any, label: str) -> str | None:
    if not isinstance(mapping, dict) or set(mapping) != _MAPPING_KEYS:
        raise FlutterConfigError(f"{label} is a malformed Code Connect mapping.")
    framework = mapping.get("framework")
    symbol = mapping.get("symbol")
    approved = mapping.get("approved")
    inferred = mapping.get("inferred")
    source_digest = mapping.get("sourceDigest")
    if not isinstance(framework, str) or not framework:
        raise FlutterConfigError(f"{label}.framework must be an exact non-empty string.")
    if not isinstance(symbol, str) or not symbol:
        raise FlutterConfigError(f"{label}.symbol must be an exact non-empty string.")
    if not isinstance(approved, bool) or not isinstance(inferred, bool):
        raise FlutterConfigError(f"{label} approval flags must be booleans.")
    if not isinstance(source_digest, str) or _DIGEST.fullmatch(source_digest) is None:
        raise FlutterConfigError(f"{label}.sourceDigest must be a lowercase SHA-256 digest.")
    if framework != "flutter":
        return None
    if approved is not True or inferred is not False:
        raise FlutterConfigError(
            f"{label} is inferred or unapproved and cannot enter the Flutter allowlist."
        )
    return _exact_code_identity(symbol, f"{label}.symbol")


def _token_flutter_symbols(token: Any, identity: str) -> list[str]:
    if not isinstance(token, dict):
        raise FlutterConfigError(f"Verified token {identity!r} is malformed.")
    extensions = token.get("extensions")
    if not isinstance(extensions, dict):
        raise FlutterConfigError(f"Verified token {identity!r} extensions are malformed.")
    if TOKEN_CODE_CONNECT_EXTENSION not in extensions:
        return []
    code_connect = extensions[TOKEN_CODE_CONNECT_EXTENSION]
    if not isinstance(code_connect, dict) or set(code_connect) != {"codeMappings"}:
        raise FlutterConfigError(
            f"Token {identity!r} has malformed Guardian Code Connect evidence."
        )
    mappings = code_connect.get("codeMappings")
    if not isinstance(mappings, list) or not mappings:
        raise FlutterConfigError(
            f"Token {identity!r} Guardian codeMappings must be a non-empty array."
        )
    symbols: list[str] = []
    for index, mapping in enumerate(mappings):
        symbol = _mapping_symbol(mapping, f"token {identity!r} codeMappings[{index}]")
        if symbol is not None:
            symbols.append(symbol)
    return symbols


def _registry_flutter_symbols(asset: Any, plural: str, index: int) -> list[str]:
    label = f"registry.{plural}[{index}]"
    if not isinstance(asset, dict):
        raise FlutterConfigError(f"{label} is malformed.")
    mappings = asset.get("codeMappings")
    if not isinstance(mappings, list):
        raise FlutterConfigError(f"{label}.codeMappings must be an array.")
    symbols: list[str] = []
    for mapping_index, mapping in enumerate(mappings):
        symbol = _mapping_symbol(mapping, f"{label}.codeMappings[{mapping_index}]")
        if symbol is not None:
            symbols.append(symbol)
    if not symbols:
        return []
    provenance = asset.get("provenance")
    figma = asset.get("figma")
    if (
        asset.get("status") != "approved"
        or asset.get("approved") is not True
        or asset.get("deprecated") is not False
        or not isinstance(provenance, dict)
        or provenance.get("published") is not True
        or not isinstance(figma, dict)
        or figma.get("published") is not True
    ):
        raise FlutterConfigError(
            f"{label} has a Flutter mapping but is not exactly approved and published."
        )
    return symbols


def _variant_identity_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise FlutterConfigError(f"{label} must be a non-empty exact identity array.")
    normalized = [_exact_code_identity(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(set(normalized)) != len(normalized):
        raise FlutterConfigError(f"{label} contains duplicate or ambiguous identities.")
    return sorted(normalized)


def _component_variant_map(asset: dict[str, Any], label: str) -> dict[str, list[str]]:
    raw_variants = asset.get("variants")
    raw_properties = asset.get("properties")
    if not isinstance(raw_variants, list) or not isinstance(raw_properties, dict):
        raise FlutterConfigError(f"{label} component variant evidence is malformed.")
    if raw_variants and "variant" in raw_properties:
        raise FlutterConfigError(
            f"{label} has ambiguous duplicate variant evidence in variants and properties."
        )
    output: dict[str, list[str]] = {}
    if raw_variants:
        output["variant"] = _variant_identity_list(raw_variants, f"{label}.variants")
    seen_values: set[str] = set(output.get("variant", []))
    for property_name in sorted(raw_properties):
        if not isinstance(property_name, str) or not property_name:
            raise FlutterConfigError(f"{label} has an invalid component variant property name.")
        values = _variant_identity_list(
            raw_properties[property_name],
            f"{label}.properties.{property_name}",
        )
        overlap = seen_values.intersection(values)
        if overlap:
            raise FlutterConfigError(
                f"{label} reuses an ambiguous variant identity across properties: {sorted(overlap)!r}."
            )
        seen_values.update(values)
        output[property_name] = values
    return output


def _add_claim(
    *,
    identity: str,
    category: str,
    source: str,
    claims: dict[str, tuple[str, str]],
    identities: dict[str, set[str]],
) -> None:
    existing = claims.get(identity)
    if existing is not None:
        raise FlutterConfigError(
            f"Flutter code identity {identity!r} is ambiguous between {existing[1]} and {source}."
        )
    claims[identity] = (category, source)
    identities[category].add(identity)


def _derive_allowlist(snapshot: Any) -> tuple[dict[str, list[str]], dict[str, Any]]:
    if not isinstance(snapshot, dict):
        raise FlutterConfigError("Verified pinned snapshot is malformed.")
    identities: dict[str, set[str]] = {category: set() for category in _IDENTITY_CATEGORIES}
    claims: dict[str, tuple[str, str]] = {}

    tokens = snapshot.get("tokens")
    if not isinstance(tokens, dict):
        raise FlutterConfigError("Verified pinned snapshot tokens are malformed.")
    for token_identity in sorted(tokens):
        token = tokens[token_identity]
        symbols = _token_flutter_symbols(token, token_identity)
        if not symbols:
            continue
        if token.get("deprecated") is not False:
            raise FlutterConfigError(
                f"Token {token_identity!r} is deprecated and cannot enter a new Flutter allowlist."
            )
        provenance = token.get("provenance") if isinstance(token, dict) else None
        if (
            token.get("approved") is not True
            or not isinstance(provenance, dict)
            or provenance.get("approval") != "explicit"
            or provenance.get("published") is not True
        ):
            raise FlutterConfigError(
                f"Token {token_identity!r} has a Flutter mapping without explicit published approval."
            )
        token_type = token.get("type")
        category = _TOKEN_TYPE_CATEGORY.get(token_type)
        if category is None:
            raise FlutterConfigError(
                f"Token {token_identity!r} has Flutter mapping for unsupported token type {token_type!r}."
            )
        for symbol in symbols:
            _add_claim(
                identity=symbol,
                category=category,
                source=f"token {token_identity!r}",
                claims=claims,
                identities=identities,
            )

    registry = snapshot.get("registry")
    if not isinstance(registry, dict) or set(registry) != {"components", "icons"}:
        raise FlutterConfigError("Verified pinned snapshot registry is malformed.")
    component_variants: dict[str, dict[str, list[str]]] = {}
    variant_identities: dict[str, str] = {}
    for plural, category, expected_kind in (
        ("components", "widgets", "component"),
        ("icons", "icons", "icon"),
    ):
        assets = registry.get(plural)
        if not isinstance(assets, list):
            raise FlutterConfigError(f"Verified registry.{plural} must be an array.")
        for index, asset in enumerate(assets):
            label = f"registry.{plural}[{index}]"
            if not isinstance(asset, dict) or asset.get("kind") != expected_kind:
                raise FlutterConfigError(f"{label} has an unsupported or conflicting asset kind.")
            symbols = _registry_flutter_symbols(asset, plural, index)
            if not symbols:
                continue
            variants = _component_variant_map(asset, label) if plural == "components" else {}
            for symbol in symbols:
                _add_claim(
                    identity=symbol,
                    category=category,
                    source=f"{label} ({asset.get('identity')!r})",
                    claims=claims,
                    identities=identities,
                )
                if variants:
                    for property_name, values in variants.items():
                        for value in values:
                            previous = variant_identities.get(value)
                            current = f"{symbol}.{property_name}"
                            if previous == current:
                                raise FlutterConfigError(
                                    f"Component variant identity {value!r} is duplicated ambiguously."
                                )
                            variant_identities.setdefault(value, current)
                    component_variants[symbol] = copy.deepcopy(variants)

    overlap = set(claims).intersection(variant_identities)
    if overlap:
        raise FlutterConfigError(
            f"Code identities cannot be both primitives and component variants: {sorted(overlap)!r}."
        )
    return (
        {category: sorted(identities[category]) for category in _IDENTITY_CATEGORIES},
        {identity: component_variants[identity] for identity in sorted(component_variants)},
    )


def _component_rule_symbol_map(
    snapshot: Any,
    approved_widgets: set[str],
) -> dict[str, list[str]]:
    """Bind canonical design identities only to approved exact Flutter constructors."""

    registry = snapshot.get("registry") if isinstance(snapshot, dict) else None
    components = registry.get("components") if isinstance(registry, dict) else None
    if not isinstance(components, list):
        raise FlutterConfigError("Verified registry.components must be an array.")
    output: dict[str, list[str]] = {}
    seen_design_identities: set[str] = set()
    for index, asset in enumerate(components):
        label = f"registry.components[{index}]"
        if not isinstance(asset, dict) or asset.get("kind") != "component":
            raise FlutterConfigError(f"{label} has an unsupported or conflicting asset kind.")
        design_identity = asset.get("identity")
        if not isinstance(design_identity, str) or not design_identity.strip():
            raise FlutterConfigError(f"{label}.identity must be an exact non-empty string.")
        if design_identity in seen_design_identities:
            raise FlutterConfigError(
                f"Design identity {design_identity!r} is duplicated ambiguously."
            )
        seen_design_identities.add(design_identity)
        symbols = _registry_flutter_symbols(asset, "components", index)
        if len(symbols) != len(set(symbols)):
            raise FlutterConfigError(
                f"{label} contains duplicate Flutter constructor mappings."
            )
        normalized = sorted(symbols)
        if any(symbol not in approved_widgets for symbol in normalized):
            raise FlutterConfigError(
                f"{label} usage-rule mapping is not an approved widget identity."
            )
        if normalized:
            output[design_identity] = normalized
    return {identity: output[identity] for identity in sorted(output)}


def _compile_usage_rules(
    snapshot: Any,
    approved_widgets: set[str] | list[str] | tuple[str, ...],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compile only v0.3.5's two exact, permission-bound rule capabilities."""

    if not isinstance(snapshot, dict):
        raise FlutterConfigError("Verified rule snapshot is malformed.")
    normalized_widgets = {
        _exact_code_identity(value, "approved widget identity")
        for value in approved_widgets
    }
    if len(normalized_widgets) != len(approved_widgets):
        raise FlutterConfigError("Approved widget identities are not unique.")
    capabilities = snapshot.get("activatedCapabilities")
    if capabilities != _ACTIVATED_USAGE_CAPABILITIES:
        raise FlutterConfigError(
            "Rule snapshot activated capabilities differ from the v0.3.5 evaluator."
        )
    rules = snapshot.get("rules")
    if not isinstance(rules, list):
        raise FlutterConfigError("Rule snapshot rules must be an array.")
    rule_ids: list[str] = []
    for rule in rules:
        rule_id = rule.get("ruleId") if isinstance(rule, dict) else None
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            raise FlutterConfigError("Rule snapshot contains an invalid ruleId.")
        rule_ids.append(rule_id)
    if rule_ids != sorted(set(rule_ids)):
        raise FlutterConfigError("Rule snapshot rules are not sorted and unique by ruleId.")

    constructor_map = _component_rule_symbol_map(snapshot, normalized_widgets)
    active: list[dict[str, Any]] = []
    inactive: list[dict[str, str]] = []
    informative: list[str] = []
    for rule in rules:
        rule_id = rule["ruleId"]
        rule_class = rule.get("class")
        if rule_class == "informative":
            informative.append(rule_id)
            continue
        if rule_class == "judgment":
            inactive.append(
                {"ruleId": rule_id, "reasonCode": "unsupported_rule_class"}
            )
            continue
        if rule_class != "machine":
            raise FlutterConfigError(f"Rule {rule_id!r} has an invalid rule class.")
        predicate = rule.get("predicate")
        if not isinstance(predicate, dict):
            raise FlutterConfigError(f"Machine rule {rule_id!r} has no exact predicate.")
        predicate_type = predicate.get("type")
        scope = predicate.get("scope")
        capability = {"predicate": predicate_type, "scope": scope}
        if capability not in _ACTIVATED_USAGE_CAPABILITIES:
            inactive.append(
                {"ruleId": rule_id, "reasonCode": "unsupported_predicate_scope"}
            )
            continue
        expected_predicate_keys = {"type", "identity", "scope"}
        if predicate_type == "max_instances_per_scope":
            expected_predicate_keys.add("max")
        if set(predicate) != expected_predicate_keys:
            raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
        design_identity = predicate.get("identity")
        if not isinstance(design_identity, str) or not design_identity.strip():
            raise FlutterConfigError(f"Machine rule {rule_id!r} identity is invalid.")
        constructors = constructor_map.get(design_identity)
        if not constructors:
            inactive.append(
                {"ruleId": rule_id, "reasonCode": "identity_not_mapped"}
            )
            continue
        compiled: dict[str, Any] = {
            "ruleId": rule_id,
            "predicate": predicate_type,
            "scope": "compilation_unit",
            "constructorIdentities": copy.deepcopy(constructors),
        }
        if predicate_type == "max_instances_per_scope":
            maximum = predicate.get("max")
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                raise FlutterConfigError(f"Machine rule {rule_id!r} maximum is invalid.")
            compiled["max"] = maximum
        active.append(compiled)

    coverage = {
        "status": "incomplete" if inactive else "complete",
        "activeRuleIds": [item["ruleId"] for item in active],
        "inactive": inactive,
        "informativeRuleIds": informative,
    }
    return active, coverage


def _compile_usage_rules_v2(
    snapshot: Any,
    approved_widgets: set[str] | list[str] | tuple[str, ...],
    component_variants: dict[str, dict[str, list[str]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compile evaluator-v2 rules from exact catalog-to-code mappings only."""

    if not isinstance(snapshot, dict):
        raise FlutterConfigError("Verified rule snapshot is malformed.")
    normalized_widgets = {
        _exact_code_identity(value, "approved widget identity")
        for value in approved_widgets
    }
    if len(normalized_widgets) != len(approved_widgets):
        raise FlutterConfigError("Approved widget identities are not unique.")
    if not isinstance(component_variants, dict):
        raise FlutterConfigError("Verified component variant mappings are malformed.")
    constructor_map = _component_rule_symbol_map(snapshot, normalized_widgets)
    rules = snapshot.get("rules")
    if not isinstance(rules, list):
        raise FlutterConfigError("Rule snapshot rules must be an array.")
    rule_ids = [rule.get("ruleId") if isinstance(rule, dict) else None for rule in rules]
    if (
        any(not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None for rule_id in rule_ids)
        or rule_ids != sorted(set(rule_ids))
    ):
        raise FlutterConfigError("Rule snapshot rules are not sorted and unique by ruleId.")

    def mapped(identity: Any, *, rule_id: str, label: str) -> list[str] | None:
        if not isinstance(identity, str) or not identity.strip():
            raise FlutterConfigError(f"Machine rule {rule_id!r} {label} is invalid.")
        return copy.deepcopy(constructor_map.get(identity))

    active: list[dict[str, Any]] = []
    inactive: list[dict[str, str]] = []
    informative: list[str] = []
    for rule in rules:
        rule_id = rule["ruleId"]
        rule_class = rule.get("class")
        if rule_class == "informative":
            informative.append(rule_id)
            continue
        if rule_class == "judgment":
            inactive.append({"ruleId": rule_id, "reasonCode": "unsupported_rule_class"})
            continue
        if rule_class != "machine":
            raise FlutterConfigError(f"Rule {rule_id!r} has an invalid rule class.")
        predicate = rule.get("predicate")
        if not isinstance(predicate, dict):
            raise FlutterConfigError(f"Machine rule {rule_id!r} has no exact predicate.")
        predicate_type = predicate.get("type")
        compiled: dict[str, Any] = {"ruleId": rule_id, "predicate": predicate_type}
        if predicate_type in {"forbidden_identity_in_scope", "max_instances_per_scope"}:
            expected = {"type", "identity", "scope"}
            if predicate_type == "max_instances_per_scope":
                expected.add("max")
            if set(predicate) != expected or predicate.get("scope") not in _USAGE_SCOPES:
                raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
            constructors = mapped(predicate.get("identity"), rule_id=rule_id, label="identity")
            if not constructors:
                inactive.append({"ruleId": rule_id, "reasonCode": "identity_not_mapped"})
                continue
            compiled.update(
                {
                    "scope": predicate["scope"],
                    "constructorIdentities": constructors,
                }
            )
            if predicate_type == "max_instances_per_scope":
                maximum = predicate.get("max")
                if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                    raise FlutterConfigError(f"Machine rule {rule_id!r} maximum is invalid.")
                compiled["max"] = maximum
        elif predicate_type == "forbidden_nesting":
            if set(predicate) != {"type", "outerIdentity", "innerIdentity"}:
                raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
            outer = mapped(predicate.get("outerIdentity"), rule_id=rule_id, label="outerIdentity")
            inner = mapped(predicate.get("innerIdentity"), rule_id=rule_id, label="innerIdentity")
            if not outer or not inner:
                inactive.append({"ruleId": rule_id, "reasonCode": "identity_not_mapped"})
                continue
            compiled.update(
                {
                    "outerConstructorIdentities": outer,
                    "innerConstructorIdentities": inner,
                }
            )
        elif predicate_type == "required_companion":
            if (
                set(predicate) != {"type", "identity", "companionIdentity", "relation"}
                or predicate.get("relation") not in _COMPANION_RELATIONS
            ):
                raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
            constructors = mapped(predicate.get("identity"), rule_id=rule_id, label="identity")
            companions = mapped(
                predicate.get("companionIdentity"),
                rule_id=rule_id,
                label="companionIdentity",
            )
            if not constructors or not companions:
                inactive.append({"ruleId": rule_id, "reasonCode": "identity_not_mapped"})
                continue
            compiled.update(
                {
                    "constructorIdentities": constructors,
                    "companionConstructorIdentities": companions,
                    "relation": predicate["relation"],
                }
            )
        elif predicate_type == "allowed_parents":
            if set(predicate) != {"type", "identity", "parents"}:
                raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
            raw_parents = predicate.get("parents")
            if (
                not isinstance(raw_parents, list)
                or not raw_parents
                or any(not isinstance(parent, str) or not parent.strip() for parent in raw_parents)
                or raw_parents != sorted(set(raw_parents))
            ):
                raise FlutterConfigError(f"Machine rule {rule_id!r} parents are invalid.")
            constructors = mapped(predicate.get("identity"), rule_id=rule_id, label="identity")
            parent_groups = [
                mapped(parent, rule_id=rule_id, label="parent identity")
                for parent in raw_parents
            ]
            if not constructors or any(not group for group in parent_groups):
                inactive.append({"ruleId": rule_id, "reasonCode": "identity_not_mapped"})
                continue
            parent_constructors = sorted(
                {identity for group in parent_groups for identity in group or []}
            )
            compiled.update(
                {
                    "constructorIdentities": constructors,
                    "parentConstructorIdentities": parent_constructors,
                }
            )
        elif predicate_type == "variant_context":
            if set(predicate) != {"type", "identity", "variant", "allowedScopes"}:
                raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is malformed.")
            allowed_scopes = predicate.get("allowedScopes")
            if (
                not isinstance(allowed_scopes, list)
                or not allowed_scopes
                or allowed_scopes != sorted(set(allowed_scopes))
                or any(scope not in _USAGE_SCOPES for scope in allowed_scopes)
            ):
                raise FlutterConfigError(f"Machine rule {rule_id!r} allowedScopes are invalid.")
            constructors = mapped(predicate.get("identity"), rule_id=rule_id, label="identity")
            raw_variant = predicate.get("variant")
            if not constructors:
                inactive.append({"ruleId": rule_id, "reasonCode": "identity_not_mapped"})
                continue
            if not isinstance(raw_variant, str) or _CODE_IDENTITY.fullmatch(raw_variant) is None:
                inactive.append({"ruleId": rule_id, "reasonCode": "variant_not_mapped"})
                continue
            matched_properties: set[str] = set()
            for constructor in constructors:
                properties = component_variants.get(constructor)
                if not isinstance(properties, dict):
                    matched_properties.clear()
                    break
                matches = [
                    property_name
                    for property_name, identities in properties.items()
                    if isinstance(identities, list) and raw_variant in identities
                ]
                if len(matches) != 1:
                    matched_properties.clear()
                    break
                matched_properties.add(matches[0])
            if len(matched_properties) != 1:
                inactive.append({"ruleId": rule_id, "reasonCode": "variant_not_mapped"})
                continue
            compiled.update(
                {
                    "constructorIdentities": constructors,
                    "variantProperty": next(iter(matched_properties)),
                    "variantIdentities": [raw_variant],
                    "allowedScopes": copy.deepcopy(allowed_scopes),
                }
            )
        else:
            raise FlutterConfigError(f"Machine rule {rule_id!r} predicate is unsupported.")
        active.append(compiled)
    return active, {
        "status": "incomplete" if inactive else "complete",
        "activeRuleIds": [item["ruleId"] for item in active],
        "inactive": inactive,
        "informativeRuleIds": informative,
    }
def _validate_usage_rule_config(
    document: dict[str, Any],
    approved_widgets: list[str],
) -> None:
    if document.get("ruleSnapshotId") != document.get("snapshotId"):
        raise FlutterConfigError("ruleSnapshotId must equal the pinned snapshotId.")
    rules_digest = document.get("rulesDigest")
    if not isinstance(rules_digest, str) or _DIGEST.fullmatch(rules_digest) is None:
        raise FlutterConfigError("Flutter adapter config rulesDigest is invalid.")
    active = document.get("activeUsageRules")
    if not isinstance(active, list):
        raise FlutterConfigError("activeUsageRules must be an array.")
    active_ids: list[str] = []
    approved_widget_set = set(approved_widgets)
    for item in active:
        if not isinstance(item, dict):
            raise FlutterConfigError("activeUsageRules contains a malformed rule.")
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
            raise FlutterConfigError("activeUsageRules contains an unsupported predicate.")
        rule_id = item.get("ruleId")
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            raise FlutterConfigError("activeUsageRules contains an invalid ruleId.")
        constructors = _variant_identity_list(
            item.get("constructorIdentities"),
            f"activeUsageRules.{rule_id}.constructorIdentities",
        )
        if any(identity not in approved_widget_set for identity in constructors):
            raise FlutterConfigError(
                "activeUsageRules constructor is not an approved widget identity."
            )
        if predicate == "max_instances_per_scope":
            maximum = item.get("max")
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                raise FlutterConfigError("activeUsageRules maximum is invalid.")
        active_ids.append(rule_id)
    if active_ids != sorted(set(active_ids)):
        raise FlutterConfigError("activeUsageRules is not sorted and unique by ruleId.")

    coverage = document.get("usageRuleCoverage")
    expected_coverage_keys = {
        "status",
        "activeRuleIds",
        "inactive",
        "informativeRuleIds",
    }
    if not isinstance(coverage, dict) or set(coverage) != expected_coverage_keys:
        raise FlutterConfigError("usageRuleCoverage has unknown or missing fields.")
    if coverage.get("activeRuleIds") != active_ids:
        raise FlutterConfigError("usageRuleCoverage activeRuleIds differs from compiled rules.")
    informative = coverage.get("informativeRuleIds")
    if (
        not isinstance(informative, list)
        or any(not isinstance(item, str) or _RULE_ID.fullmatch(item) is None for item in informative)
        or informative != sorted(set(informative))
    ):
        raise FlutterConfigError("usageRuleCoverage informativeRuleIds is invalid.")
    inactive = coverage.get("inactive")
    if not isinstance(inactive, list):
        raise FlutterConfigError("usageRuleCoverage inactive must be an array.")
    inactive_ids: list[str] = []
    for item in inactive:
        if (
            not isinstance(item, dict)
            or set(item) != {"ruleId", "reasonCode"}
            or not isinstance(item.get("ruleId"), str)
            or _RULE_ID.fullmatch(item["ruleId"]) is None
            or item.get("reasonCode") not in _INACTIVE_USAGE_RULE_REASONS
        ):
            raise FlutterConfigError("usageRuleCoverage contains invalid inactive metadata.")
        inactive_ids.append(item["ruleId"])
    if inactive_ids != sorted(set(inactive_ids)):
        raise FlutterConfigError("usageRuleCoverage inactive rules are not sorted and unique.")
    all_ids = active_ids + inactive_ids + informative
    if len(all_ids) != len(set(all_ids)):
        raise FlutterConfigError("usageRuleCoverage rule classes overlap.")
    expected_status = "incomplete" if inactive else "complete"
    if coverage.get("status") != expected_status:
        raise FlutterConfigError("usageRuleCoverage status differs from inactive evidence.")


def _validate_usage_rule_config_v3(
    document: dict[str, Any],
    approved_widgets: list[str],
    component_variants: dict[str, Any],
) -> None:
    if document.get("ruleSnapshotId") != document.get("snapshotId"):
        raise FlutterConfigError("ruleSnapshotId must equal the pinned snapshotId.")
    for field in ("rulesDigest", "evaluatorContractDigest", "authorizationDigest"):
        value = document.get(field)
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise FlutterConfigError(f"Flutter adapter config {field} is invalid.")
    if document.get("evaluatorId") != TARGET_EVALUATOR_ID:
        raise FlutterConfigError("Flutter adapter config evaluatorId is unsupported.")
    if document.get("evaluatorContractDigest") != EVALUATOR_CONTRACT_DIGEST:
        raise FlutterConfigError("Flutter adapter evaluator contract is unsupported.")
    run_id = document.get("runId")
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        raise FlutterConfigError("Flutter adapter config runId is invalid.")

    active = document.get("activeUsageRules")
    if not isinstance(active, list):
        raise FlutterConfigError("activeUsageRules must be an array.")
    approved_widget_set = set(approved_widgets)
    active_ids: list[str] = []
    for item in active:
        if not isinstance(item, dict):
            raise FlutterConfigError("activeUsageRules contains a malformed rule.")
        predicate = item.get("predicate")
        expected_by_predicate = {
            "forbidden_identity_in_scope": {
                "ruleId", "predicate", "scope", "constructorIdentities",
            },
            "max_instances_per_scope": {
                "ruleId", "predicate", "scope", "constructorIdentities", "max",
            },
            "forbidden_nesting": {
                "ruleId", "predicate", "outerConstructorIdentities",
                "innerConstructorIdentities",
            },
            "required_companion": {
                "ruleId", "predicate", "constructorIdentities",
                "companionConstructorIdentities", "relation",
            },
            "allowed_parents": {
                "ruleId", "predicate", "constructorIdentities",
                "parentConstructorIdentities",
            },
            "variant_context": {
                "ruleId", "predicate", "constructorIdentities", "variantProperty",
                "variantIdentities", "allowedScopes",
            },
        }
        expected = expected_by_predicate.get(predicate)
        if expected is None or set(item) != expected:
            raise FlutterConfigError("activeUsageRules contains an unsupported predicate.")
        rule_id = item.get("ruleId")
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            raise FlutterConfigError("activeUsageRules contains an invalid ruleId.")

        identity_fields = {
            "forbidden_identity_in_scope": ("constructorIdentities",),
            "max_instances_per_scope": ("constructorIdentities",),
            "forbidden_nesting": (
                "outerConstructorIdentities", "innerConstructorIdentities",
            ),
            "required_companion": (
                "constructorIdentities", "companionConstructorIdentities",
            ),
            "allowed_parents": (
                "constructorIdentities", "parentConstructorIdentities",
            ),
            "variant_context": ("constructorIdentities", "variantIdentities"),
        }[predicate]
        normalized: dict[str, list[str]] = {}
        for field in identity_fields:
            normalized[field] = _variant_identity_list(
                item.get(field), f"activeUsageRules.{rule_id}.{field}"
            )
        constructor_fields = [
            field for field in identity_fields if field != "variantIdentities"
        ]
        if any(
            identity not in approved_widget_set
            for field in constructor_fields
            for identity in normalized[field]
        ):
            raise FlutterConfigError(
                "activeUsageRules constructor is not an approved widget identity."
            )

        if predicate in {"forbidden_identity_in_scope", "max_instances_per_scope"}:
            if item.get("scope") not in _USAGE_SCOPES:
                raise FlutterConfigError("activeUsageRules scope is invalid.")
        if predicate == "max_instances_per_scope":
            maximum = item.get("max")
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                raise FlutterConfigError("activeUsageRules maximum is invalid.")
        if predicate == "required_companion" and item.get("relation") not in _COMPANION_RELATIONS:
            raise FlutterConfigError("activeUsageRules companion relation is invalid.")
        if predicate == "variant_context":
            variant_property = item.get("variantProperty")
            allowed_scopes = item.get("allowedScopes")
            if not isinstance(variant_property, str) or not variant_property:
                raise FlutterConfigError("activeUsageRules variantProperty is invalid.")
            if (
                not isinstance(allowed_scopes, list)
                or not allowed_scopes
                or allowed_scopes != sorted(set(allowed_scopes))
                or any(scope not in _USAGE_SCOPES for scope in allowed_scopes)
            ):
                raise FlutterConfigError("activeUsageRules allowedScopes are invalid.")
            for constructor in normalized["constructorIdentities"]:
                properties = component_variants.get(constructor)
                mapped = properties.get(variant_property) if isinstance(properties, dict) else None
                if (
                    not isinstance(mapped, list)
                    or any(identity not in mapped for identity in normalized["variantIdentities"])
                ):
                    raise FlutterConfigError(
                        "activeUsageRules variant is not exactly mapped to its constructor."
                    )
        active_ids.append(rule_id)
    if active_ids != sorted(set(active_ids)):
        raise FlutterConfigError("activeUsageRules is not sorted and unique by ruleId.")

    coverage = document.get("usageRuleCoverage")
    if not isinstance(coverage, dict) or set(coverage) != {
        "status", "activeRuleIds", "inactive", "informativeRuleIds",
    }:
        raise FlutterConfigError("usageRuleCoverage has unknown or missing fields.")
    if coverage.get("activeRuleIds") != active_ids:
        raise FlutterConfigError("usageRuleCoverage activeRuleIds differs from compiled rules.")
    informative = coverage.get("informativeRuleIds")
    if (
        not isinstance(informative, list)
        or any(not isinstance(item, str) or _RULE_ID.fullmatch(item) is None for item in informative)
        or informative != sorted(set(informative))
    ):
        raise FlutterConfigError("usageRuleCoverage informativeRuleIds is invalid.")
    inactive = coverage.get("inactive")
    if not isinstance(inactive, list):
        raise FlutterConfigError("usageRuleCoverage inactive must be an array.")
    inactive_ids: list[str] = []
    for item in inactive:
        if (
            not isinstance(item, dict)
            or set(item) != {"ruleId", "reasonCode"}
            or not isinstance(item.get("ruleId"), str)
            or _RULE_ID.fullmatch(item["ruleId"]) is None
            or item.get("reasonCode") not in _INACTIVE_USAGE_RULE_REASONS
        ):
            raise FlutterConfigError("usageRuleCoverage contains invalid inactive metadata.")
        inactive_ids.append(item["ruleId"])
    if inactive_ids != sorted(set(inactive_ids)):
        raise FlutterConfigError("usageRuleCoverage inactive rules are not sorted and unique.")
    all_ids = active_ids + inactive_ids + informative
    if len(all_ids) != len(set(all_ids)):
        raise FlutterConfigError("usageRuleCoverage rule classes overlap.")
    if coverage.get("status") != ("incomplete" if inactive else "complete"):
        raise FlutterConfigError("usageRuleCoverage status differs from inactive evidence.")


def _validate_config_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise FlutterConfigError("Flutter adapter config must be an object.")
    schema_version = document.get("schemaVersion")
    expected_keys = (
        _CONFIG_V1_KEYS
        if schema_version == 1
        else _CONFIG_V2_KEYS
        if schema_version == 2
        else _CONFIG_V3_KEYS
        if schema_version == 3
        else None
    )
    if expected_keys is None or set(document) != expected_keys:
        raise FlutterConfigError("Flutter adapter config has unknown or missing fields.")
    if (
        document.get("adapter") != "flutter"
        or document.get("adapterVersion") != ADAPTER_VERSION
    ):
        raise FlutterConfigError("Flutter adapter config schema or adapter version is unsupported.")
    profile_id = document.get("profileId")
    if not isinstance(profile_id, str) or _PROFILE_ID.fullmatch(profile_id) is None:
        raise FlutterConfigError("Flutter adapter config profileId is invalid.")
    for field in ("policyDigest", "snapshotId", "sourceCutDigest", "configDigest"):
        value = document.get(field)
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise FlutterConfigError(f"Flutter adapter config {field} is not a lowercase digest.")
    approved = document.get("approvedIdentities")
    if not isinstance(approved, dict) or set(approved) != set(_IDENTITY_CATEGORIES):
        raise FlutterConfigError("Flutter adapter approvedIdentities categories are not canonical.")
    for category in _IDENTITY_CATEGORIES:
        values = approved.get(category)
        if not isinstance(values, list):
            raise FlutterConfigError(f"approvedIdentities.{category} must be an array.")
        normalized = [_exact_code_identity(item, f"approvedIdentities.{category}") for item in values]
        if normalized != sorted(set(normalized)):
            raise FlutterConfigError(f"approvedIdentities.{category} is not sorted and unique.")
    if schema_version == 2:
        _validate_usage_rule_config(document, approved["widgets"])
    variants = document.get("componentVariants")
    if not isinstance(variants, dict):
        raise FlutterConfigError("Flutter adapter componentVariants must be an object.")
    for widget, properties in variants.items():
        _exact_code_identity(widget, "componentVariants widget")
        if widget not in approved["widgets"] or not isinstance(properties, dict) or not properties:
            raise FlutterConfigError("componentVariants must bind a non-empty map to an approved widget.")
        for property_name, values in properties.items():
            if not isinstance(property_name, str) or not property_name:
                raise FlutterConfigError("componentVariants property name is invalid.")
            _variant_identity_list(values, f"componentVariants.{widget}.{property_name}")
    if schema_version == 3:
        _validate_usage_rule_config_v3(
            document, approved["widgets"], variants
        )
    try:
        normalized_approved = validate_approved_package_bindings(
            document.get("approvedPackages"), approved, variants
        )
        validate_required_package_bindings(
            document.get("requiredPackages"), approved_packages=normalized_approved
        )
        toolchain = validate_toolchain_binding(document.get("toolchain"))
        if toolchain["platformId"] != current_platform_id():
            raise FlutterToolchainIntegrityError(
                "Flutter adapter toolchain does not match the current host platform."
            )
    except (FlutterPackageProvenanceError, FlutterToolchainIntegrityError) as error:
        raise FlutterConfigError(str(error)) from error
    unsigned = copy.deepcopy(document)
    claimed_digest = unsigned.pop("configDigest")
    if sha256_digest(unsigned) != claimed_digest:
        raise FlutterConfigError("configDigest does not match canonical Flutter adapter content.")
    return copy.deepcopy(document)


def _generate_flutter_adapter_config_at_home(
    home: Path,
    *,
    profile_id: str,
    run_id: str,
) -> dict[str, Any]:
    """Derive one canonical Flutter allowlist from a verified sealed run pin."""

    normalized_home = home.expanduser().absolute()
    try:
        policy_digest = verify_policy_anchor(normalized_home)
        pinned = load_run_pin(
            normalized_home,
            profile_id=profile_id,
            run_id=run_id,
            policy_digest=policy_digest,
        )
    except (OSError, ValueError) as error:
        raise FlutterConfigError(f"Verified Flutter run pin cannot be loaded: {error}") from error
    profile = pinned.get("profile")
    pin = pinned.get("pin")
    snapshot = pinned.get("snapshot")
    if not isinstance(profile, dict) or not isinstance(profile.get("adapters"), dict):
        raise FlutterConfigError("Pinned profile adapter configuration is malformed.")
    flutter_adapter = profile["adapters"].get("flutter")
    if flutter_adapter is None or flutter_adapter == {"enabled": False}:
        raise FlutterAdapterUnsupportedError(
            "Flutter adapter is not exactly enabled by the selected profile."
        )
    if (
        not isinstance(flutter_adapter, dict)
        or set(flutter_adapter)
        != {"enabled", "platformArtifacts", "requiredPackages"}
        or flutter_adapter.get("enabled") is not True
    ):
        raise FlutterConfigError("Flutter adapter configuration is invalid or non-canonical.")
    try:
        toolchain = select_profile_toolchain(flutter_adapter["platformArtifacts"])
        required_packages = validate_required_package_bindings(
            flutter_adapter["requiredPackages"]
        )
    except (FlutterPackageProvenanceError, FlutterToolchainIntegrityError) as error:
        raise FlutterConfigError(str(error)) from error
    if not isinstance(pin, dict) or not isinstance(snapshot, dict):
        raise FlutterConfigError("Verified Flutter run pin response is malformed.")
    approved_identities, component_variants = _derive_allowlist(snapshot)
    has_flutter_identities = any(approved_identities.values())
    source_cut = pin.get("sourceCut")
    if not isinstance(source_cut, dict):
        raise FlutterConfigError("Verified run pin sourceCut is malformed.")
    if has_flutter_identities and (
        not isinstance(source_cut.get("codeConnectParseDigest"), str)
        or _DIGEST.fullmatch(source_cut["codeConnectParseDigest"]) is None
        or not isinstance(source_cut.get("repositoryCommit"), str)
        or not source_cut["repositoryCommit"]
    ):
        raise FlutterConfigError("Flutter identities require complete pinned Code Connect provenance.")
    try:
        approved_packages = derive_approved_packages(
            snapshot,
            approved_identities,
            component_variants,
            repository_commit=source_cut.get("repositoryCommit"),
        )
    except FlutterPackageProvenanceError as error:
        raise FlutterConfigError(str(error)) from error
    snapshot_schema = snapshot.get("schemaVersion")
    if snapshot_schema not in {1, 2}:
        raise FlutterConfigError("Pinned snapshot schema is unsupported by the Flutter adapter.")
    evaluator_authorization: dict[str, Any] | None = None
    if snapshot_schema == 2:
        try:
            evaluator_authorization = load_evaluator_authorization(
                normalized_home, profile_id
            )
        except EvaluatorUpgradeError as error:
            raise FlutterConfigError(
                f"Evaluator-v2 authorization cannot be verified: {error}"
            ) from error
    config_schema = 3 if evaluator_authorization is not None else snapshot_schema
    unsigned = {
        "schemaVersion": config_schema,
        "adapter": "flutter",
        "adapterVersion": ADAPTER_VERSION,
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "approvedPackages": approved_packages,
        "approvedIdentities": approved_identities,
        "toolchain": toolchain,
        "requiredPackages": required_packages,
        "componentVariants": component_variants,
    }
    if snapshot_schema == 2:
        snapshot_id = snapshot.get("snapshotId")
        rules = snapshot.get("rules")
        rules_digest = snapshot.get("rulesDigest")
        rule_evidence = snapshot.get("ruleEvidence")
        rule_validation = snapshot.get("ruleValidation")
        if (
            snapshot_id != pin.get("snapshotId")
            or not isinstance(snapshot_id, str)
            or _DIGEST.fullmatch(snapshot_id) is None
        ):
            raise FlutterConfigError("Rule snapshot identity differs from the sealed run pin.")
        if (
            not isinstance(rules, list)
            or not isinstance(rules_digest, str)
            or _DIGEST.fullmatch(rules_digest) is None
            or sha256_digest(rules) != rules_digest
        ):
            raise FlutterConfigError("Rule snapshot rulesDigest does not bind canonical rules.")
        if (
            not isinstance(rule_evidence, dict)
            or rule_evidence.get("captureAttempted") is not True
            or rule_evidence.get("sourceComplete") is not True
        ):
            raise FlutterConfigError("Rule source capture is incomplete.")
        if not isinstance(rule_validation, dict):
            raise FlutterConfigError("Rule validation evidence is malformed.")
        if evaluator_authorization is None:
            if rule_validation.get("status") != "allowed":
                raise FlutterConfigError(
                    "Rule validation is not allowed for production analysis."
                )
            active_rules, rule_coverage = _compile_usage_rules(
                snapshot,
                set(approved_identities["widgets"]),
            )
        else:
            if rule_validation.get("status") not in {"allowed", "not_assessed"}:
                raise FlutterConfigError(
                    "Rule validation is invalid for evaluator-v2 analysis."
                )
            if (
                evaluator_authorization.get("evaluatorId") != TARGET_EVALUATOR_ID
                or evaluator_authorization.get("evaluatorContractDigest")
                != EVALUATOR_CONTRACT_DIGEST
                or evaluator_authorization.get("capabilityMatrix")
                != EVALUATOR_CAPABILITY_MATRIX
                or not isinstance(
                    evaluator_authorization.get("authorizationDigest"), str
                )
                or _DIGEST.fullmatch(
                    evaluator_authorization["authorizationDigest"]
                )
                is None
            ):
                raise FlutterConfigError(
                    "Evaluator-v2 authorization does not match the supported contract."
                )
            active_rules, rule_coverage = _compile_usage_rules_v2(
                snapshot,
                set(approved_identities["widgets"]),
                component_variants,
            )
        unsigned.update(
            {
                "ruleSnapshotId": snapshot_id,
                "rulesDigest": rules_digest,
                "activeUsageRules": active_rules,
                "usageRuleCoverage": rule_coverage,
            }
        )
        if evaluator_authorization is not None:
            unsigned.update(
                {
                    "runId": pin["runId"],
                    "evaluatorId": TARGET_EVALUATOR_ID,
                    "evaluatorContractDigest": EVALUATOR_CONTRACT_DIGEST,
                    "authorizationDigest": evaluator_authorization[
                        "authorizationDigest"
                    ],
                }
            )
    config = {**unsigned, "configDigest": sha256_digest(unsigned)}
    return _validate_config_document(config)

def generate_flutter_adapter_config(
    *,
    profile_id: str,
    run_id: str,
) -> dict[str, Any]:
    """Derive one config through the canonical host-owned Guardian trust root."""

    return _generate_flutter_adapter_config_at_home(
        default_guardian_home(),
        profile_id=profile_id,
        run_id=run_id,
    )


def write_flutter_adapter_config(
    config: dict[str, Any],
    *,
    output_path: Path,
) -> Path:
    """Atomically write a verified config only to the caller's explicit path."""

    normalized = _validate_config_document(config)
    if not isinstance(output_path, Path):
        raise FlutterConfigError("output_path must be an explicit pathlib.Path.")
    try:
        atomic_write_json(output_path, normalized)
        if output_path.read_bytes() != canonical_json_bytes(normalized):
            raise FlutterConfigError("Written Flutter adapter config is not canonical JSON.")
    except FlutterConfigError:
        raise
    except OSError as error:
        raise FlutterConfigError(f"Flutter adapter config cannot be written atomically: {error}") from error
    return output_path


__all__ = [
    "ADAPTER_VERSION",
    "TOKEN_CODE_CONNECT_EXTENSION",
    "FlutterConfigError",
    "FlutterAdapterUnsupportedError",
    "generate_flutter_adapter_config",
    "write_flutter_adapter_config",
]

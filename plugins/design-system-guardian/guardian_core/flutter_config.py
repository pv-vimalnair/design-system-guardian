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

_CONFIG_KEYS = {
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
_CODE_IDENTITY = re.compile(
    r"^(?:dart|package):[^#\s]+#[A-Za-z_$][A-Za-z0-9_$.]*$"
)


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


def _validate_config_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != _CONFIG_KEYS:
        raise FlutterConfigError("Flutter adapter config has unknown or missing fields.")
    if (
        document.get("schemaVersion") != 1
        or document.get("adapter") != "flutter"
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
    unsigned = {
        "schemaVersion": 1,
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

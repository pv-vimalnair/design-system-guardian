"""Local, task-scoped design-system selection for individual Guardian users.

Display names are intentionally excluded from every authority digest.  Only
stable Figma identities, exact versions, the project binding, and canonical
catalog content can authorize a personal task.
"""

from __future__ import annotations

import copy
import stat
from pathlib import Path
from typing import Any

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import read_canonical_json, sha256_digest
from .contracts import ExitCode
from .dtcg import DtcgValidationError, resolve_token_document
from .dtcg_resolver import materialize_resolver_tokens
from .errors import GuardianError
from .paths import (
    GuardianPaths,
    PathIntegrityError,
    assert_guardian_storage_path,
    is_link_or_reparse,
    validate_profile_id,
    validate_run_id,
)
from .policy import EXPECTED_POLICY_SHA256, verify_policy_anchor
from .profile import install_profile, load_profile
from .project_binding import ProjectBindingError, capture_project_binding
from .snapshot import ingest_snapshot, load_snapshot
from .storage import exclusive_write_json


class PersonalSelectionError(ValueError):
    """Raised when personal selection evidence is incomplete or has drifted."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


_DISCOVERY_KEYS = {
    "schemaVersion",
    "projectRoot",
    "targetFigmaFile",
    "discoveryComplete",
    "candidates",
    "adapters",
    "catalog",
    "catalogReadback",
}
_TARGET_KEYS = {"fileKey", "version", "name"}
_CANDIDATE_KEYS = {"fileKey", "version", "name", "published", "decision"}
_PERMISSION_UNSIGNED_KEYS = {
    "schemaVersion",
    "action",
    "authorityMode",
    "runId",
    "policyDigest",
    "projectRoot",
    "projectBindingDigest",
    "targetFigmaFile",
    "libraryDecisions",
    "catalogInputDigest",
    "catalogReadbackDigest",
    "adaptersDigest",
}
_PERMISSION_KEYS = _PERMISSION_UNSIGNED_KEYS | {"bindingDigest", "granted"}
_SELECTION_UNSIGNED_KEYS = {
    "schemaVersion",
    "authorityMode",
    "runId",
    "profileId",
    "profileDigest",
    "snapshotId",
    "catalogDigest",
    "policyDigest",
    "projectBindingDigest",
    "targetFigmaFile",
    "libraryDecisions",
    "selectedLibraryFileKeys",
    "excludedLibraryFileKeys",
    "selectionSetDigest",
    "permissionBindingDigest",
    "catalogReadbackDigest",
    "discoveryDigest",
}
_SELECTION_KEYS = _SELECTION_UNSIGNED_KEYS | {"selectionDigest", "authoritySeal"}
_SELECTION_PURPOSE_PREFIX = "personal-task-selection:v1:"
_CATALOG_READBACK_KEYS = {
    "schemaVersion",
    "method",
    "complete",
    "evidenceAuthority",
    "contractDigest",
    "sources",
    "tokens",
    "assets",
}
_CATALOG_READBACK_SOURCE_KEYS = {"fileKey", "version", "published"}
_CATALOG_READBACK_TOKEN_KEYS = {"identity", "published", "binding", "tokenDigest"}
_CATALOG_READBACK_ASSET_KEYS = {
    "kind",
    "identity",
    "sourceVersion",
    "figma",
    "designContractDigest",
    "codeMappingsDigest",
}
_VARIABLE_BINDING_KEYS = {
    "bindingType",
    "fileKey",
    "sourceVersion",
    "key",
    "collectionKey",
    "resolvedType",
}
_STYLE_BINDING_KEYS = {
    "bindingType",
    "fileKey",
    "sourceVersion",
    "key",
    "styleType",
}
_FIGMA_ASSET_KEYS = {"fileKey", "nodeId", "assetKey", "published"}
_CATALOG_READBACK_CONTRACT = {
    "schemaVersion": 1,
    "method": "figma_plugin_api_catalog_readback",
    "evidenceAuthority": "unprotected_caller_carried",
    "identityPolicy": "exact_one_to_one",
    "tokenContentBinding": "resolved_value_mode_type_metadata_sha256",
    "assetContentBinding": "variants_properties_and_code_mappings_sha256",
    "productCopyCollected": False,
}


def personal_catalog_readback_digest() -> str:
    """Return the fixed digest for personal local catalog read-back evidence."""

    return sha256_digest(_CATALOG_READBACK_CONTRACT)


def _require_exact_object(
    value: Any,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PersonalSelectionError(f"{label} has unknown or missing fields.")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonalSelectionError(f"{label} must be a non-empty exact string.")
    return value

def _normalize_figma_binding(
    value: Any,
    *,
    selected_versions: dict[str, str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PersonalSelectionError(f"{label} must be an exact Figma binding object.")
    binding_type = value.get("bindingType")
    keys = (
        _VARIABLE_BINDING_KEYS
        if binding_type == "variable"
        else _STYLE_BINDING_KEYS
        if binding_type == "style"
        else None
    )
    if keys is None or set(value) != keys:
        raise PersonalSelectionError(f"{label} has incomplete Figma identity fields.")
    normalized = copy.deepcopy(value)
    for field in keys - {"bindingType"}:
        _require_text(normalized.get(field), f"{label}.{field}")
    file_key = normalized["fileKey"]
    if file_key not in selected_versions:
        raise PersonalSelectionError(
            f"{label} originates outside the selected Figma libraries."
        )
    if normalized["sourceVersion"] != selected_versions[file_key]:
        raise PersonalSelectionError(f"{label} source version has drifted.")
    if (
        binding_type == "style"
        and normalized["styleType"] not in {"paint", "text", "effect", "grid"}
    ):
        raise PersonalSelectionError(f"{label}.styleType is unsupported.")
    return normalized


def _resolved_catalog_tokens(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    try:
        if "resolver" in catalog:
            return materialize_resolver_tokens(
                catalog.get("tokens"),
                catalog["resolver"],
                catalog.get("resolverContext"),
            )["tokens"]
        return resolve_token_document(catalog.get("tokens"))
    except (DtcgValidationError, KeyError, TypeError, ValueError) as error:
        raise PersonalSelectionError(
            f"Personal catalog tokens cannot be resolved exactly: {error}"
        ) from error


def _normalize_catalog_readback(
    value: Any,
    *,
    catalog: dict[str, Any],
    selected: list[dict[str, Any]],
) -> dict[str, Any]:
    readback = _require_exact_object(
        value,
        _CATALOG_READBACK_KEYS,
        "catalogReadback",
    )
    if (
        readback.get("schemaVersion") != 1
        or readback.get("method") != "figma_plugin_api_catalog_readback"
        or readback.get("complete") is not True
        or readback.get("evidenceAuthority") != "unprotected_caller_carried"
        or readback.get("contractDigest") != personal_catalog_readback_digest()
    ):
        raise PersonalSelectionError(
            "Catalog read-back contract, completeness, or local authority is invalid."
        )

    selected_versions = {item["fileKey"]: item["version"] for item in selected}
    raw_sources = readback.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise PersonalSelectionError(
            "Catalog read-back must cover every selected Figma library."
        )
    sources: list[dict[str, Any]] = []
    source_keys: set[str] = set()
    for index, raw in enumerate(raw_sources):
        source = _require_exact_object(
            raw,
            _CATALOG_READBACK_SOURCE_KEYS,
            f"catalogReadback.sources[{index}]",
        )
        file_key = _require_text(
            source.get("fileKey"),
            f"catalogReadback.sources[{index}].fileKey",
        )
        version = _require_text(
            source.get("version"),
            f"catalogReadback.sources[{index}].version",
        )
        if (
            file_key in source_keys
            or selected_versions.get(file_key) != version
            or source.get("published") is not True
        ):
            raise PersonalSelectionError(
                "Catalog read-back sources must exactly match every selected published library and version."
            )
        source_keys.add(file_key)
        sources.append(
            {"fileKey": file_key, "version": version, "published": True}
        )
    if source_keys != set(selected_versions):
        raise PersonalSelectionError(
            "Catalog read-back source coverage is incomplete or contains an unselected library."
        )

    resolved_tokens = _resolved_catalog_tokens(catalog)
    raw_tokens = readback.get("tokens")
    if not isinstance(raw_tokens, list):
        raise PersonalSelectionError("catalogReadback.tokens must be an array.")
    tokens: list[dict[str, Any]] = []
    token_identities: set[str] = set()
    token_locators: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_tokens):
        proof = _require_exact_object(
            raw,
            _CATALOG_READBACK_TOKEN_KEYS,
            f"catalogReadback.tokens[{index}]",
        )
        identity = _require_text(
            proof.get("identity"),
            f"catalogReadback.tokens[{index}].identity",
        )
        if identity in token_identities or proof.get("published") is not True:
            raise PersonalSelectionError(
                "Catalog token read-back identities must be unique and published."
            )
        binding = _normalize_figma_binding(
            proof.get("binding"),
            selected_versions=selected_versions,
            label=f"catalogReadback.tokens[{index}].binding",
        )
        token = resolved_tokens.get(identity)
        locator = (
            binding["bindingType"],
            binding["fileKey"],
            binding["key"],
        )
        if locator in token_locators:
            raise PersonalSelectionError(
                "One Figma token locator cannot prove multiple canonical token identities."
            )
        token_locators.add(locator)
        extensions = token.get("extensions") if isinstance(token, dict) else None
        if (
            not isinstance(extensions, dict)
            or extensions.get("guardian.figma") != binding
        ):
            raise PersonalSelectionError(
                f"Catalog token {identity!r} does not match its exact Figma read-back binding."
            )
        token_digest = _require_text(
            proof.get("tokenDigest"),
            f"catalogReadback.tokens[{index}].tokenDigest",
        )
        if token_digest != sha256_digest(token):
            raise PersonalSelectionError(
                f"Catalog token {identity!r} value, mode, type, or metadata differs "
                "from its exact read-back."
            )
        token_identities.add(identity)
        tokens.append(
            {
                "identity": identity,
                "published": True,
                "binding": binding,
                "tokenDigest": token_digest,
            }
        )
    if token_identities != set(resolved_tokens):
        raise PersonalSelectionError(
            "Catalog token read-back coverage is not one-to-one with the canonical token catalog."
        )

    registry = catalog.get("registry")
    if not isinstance(registry, dict) or set(registry) != {"components", "icons"}:
        raise PersonalSelectionError(
            "catalog.registry must contain components and icons arrays."
        )
    expected_assets: dict[tuple[str, str], dict[str, Any]] = {}
    for plural, kind in (("components", "component"), ("icons", "icon")):
        values = registry[plural]
        if not isinstance(values, list):
            raise PersonalSelectionError(f"catalog.registry.{plural} must be an array.")
        for raw_asset in values:
            if not isinstance(raw_asset, dict) or not isinstance(
                raw_asset.get("figma"), dict
            ):
                raise PersonalSelectionError(
                    "Catalog registry assets require exact Figma identity fields."
                )
            figma = raw_asset["figma"]
            if figma.get("fileKey") not in selected_versions:
                continue
            identity = _require_text(
                raw_asset.get("identity"),
                f"catalog.registry.{plural}.identity",
            )
            key = (kind, identity)
            if key in expected_assets:
                raise PersonalSelectionError(
                    "Catalog registry identities must be unique within each asset kind."
                )
            expected_assets[key] = raw_asset

    raw_assets = readback.get("assets")
    if not isinstance(raw_assets, list):
        raise PersonalSelectionError("catalogReadback.assets must be an array.")
    assets: list[dict[str, Any]] = []
    asset_keys: set[tuple[str, str]] = set()
    locators: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_assets):
        proof = _require_exact_object(
            raw,
            _CATALOG_READBACK_ASSET_KEYS,
            f"catalogReadback.assets[{index}]",
        )
        kind = proof.get("kind")
        if kind not in {"component", "icon"}:
            raise PersonalSelectionError(
                f"catalogReadback.assets[{index}].kind is unsupported."
            )
        identity = _require_text(
            proof.get("identity"),
            f"catalogReadback.assets[{index}].identity",
        )
        key = (kind, identity)
        if key in asset_keys or key not in expected_assets:
            raise PersonalSelectionError(
                "Catalog asset read-back contains a duplicate, invented, or unselected identity."
            )
        source_version = _require_text(
            proof.get("sourceVersion"),
            f"catalogReadback.assets[{index}].sourceVersion",
        )
        figma = _require_exact_object(
            proof.get("figma"),
            _FIGMA_ASSET_KEYS,
            f"catalogReadback.assets[{index}].figma",
        )
        normalized_figma = copy.deepcopy(figma)
        for field in ("fileKey", "nodeId", "assetKey"):
            _require_text(
                normalized_figma.get(field),
                f"catalogReadback.assets[{index}].figma.{field}",
            )
        file_key = normalized_figma["fileKey"]
        if (
            selected_versions.get(file_key) != source_version
            or normalized_figma.get("published") is not True
        ):
            raise PersonalSelectionError(
                "Catalog asset read-back is not pinned to one selected published library version."
            )
        expected = expected_assets[key]
        if (
            expected.get("sourceVersion") != source_version
            or expected.get("figma") != normalized_figma
        ):
            raise PersonalSelectionError(
                f"Catalog asset {identity!r} does not match its exact Figma read-back identity."
            )
        design_contract_digest = _require_text(
            proof.get("designContractDigest"),
            f"catalogReadback.assets[{index}].designContractDigest",
        )
        code_mappings_digest = _require_text(
            proof.get("codeMappingsDigest"),
            f"catalogReadback.assets[{index}].codeMappingsDigest",
        )
        expected_design_contract_digest = sha256_digest(
            {
                "variants": expected.get("variants"),
                "properties": expected.get("properties"),
            }
        )
        if (
            design_contract_digest != expected_design_contract_digest
            or code_mappings_digest != sha256_digest(expected.get("codeMappings"))
        ):
            raise PersonalSelectionError(
                f"Catalog asset {identity!r} variants, properties, or code mappings "
                "differ from its exact read-back."
            )
        locator = (
            normalized_figma["fileKey"],
            normalized_figma["nodeId"],
            normalized_figma["assetKey"],
        )
        if locator in locators:
            raise PersonalSelectionError(
                "One Figma catalog locator cannot prove multiple asset identities."
            )
        locators.add(locator)
        asset_keys.add(key)
        assets.append(
            {
                "kind": kind,
                "identity": identity,
                "sourceVersion": source_version,
                "figma": normalized_figma,
                "designContractDigest": design_contract_digest,
                "codeMappingsDigest": code_mappings_digest,
            }
        )
    if asset_keys != set(expected_assets):
        raise PersonalSelectionError(
            "Catalog asset read-back coverage is not one-to-one with selected registry identities."
        )

    return {
        "schemaVersion": 1,
        "method": "figma_plugin_api_catalog_readback",
        "complete": True,
        "evidenceAuthority": "unprotected_caller_carried",
        "contractDigest": personal_catalog_readback_digest(),
        "sources": sorted(sources, key=lambda item: item["fileKey"]),
        "tokens": sorted(tokens, key=lambda item: item["identity"]),
        "assets": sorted(
            assets,
            key=lambda item: (item["kind"], item["identity"]),
        ),
    }



def _selection_path(home: Path, run_id: str) -> Path:
    try:
        safe_run_id = validate_run_id(run_id)
        normalized_home = home.expanduser().absolute()
        return assert_guardian_storage_path(
            normalized_home,
            normalized_home / "personal" / "task-selections" / f"{safe_run_id}.json",
        )
    except (PathIntegrityError, TypeError, ValueError) as error:
        raise PersonalSelectionError(str(error)) from error


def _identity_target(value: Any) -> dict[str, str]:
    target = _require_exact_object(value, _TARGET_KEYS, "targetFigmaFile")
    return {
        "fileKey": _require_text(target.get("fileKey"), "targetFigmaFile.fileKey"),
        "version": _require_text(target.get("version"), "targetFigmaFile.version"),
    }


def _display_target(value: Any) -> dict[str, str]:
    target = _require_exact_object(value, _TARGET_KEYS, "targetFigmaFile")
    identity = _identity_target(target)
    return {
        **identity,
        "name": _require_text(target.get("name"), "targetFigmaFile.name"),
    }


def _normalize_project_root(value: Any) -> tuple[str, dict[str, Any]]:
    supplied = _require_text(value, "projectRoot")
    if not Path(supplied).is_absolute():
        raise PersonalSelectionError("projectRoot must be an absolute canonical path.")
    try:
        binding = capture_project_binding(supplied)
    except ProjectBindingError as error:
        raise PersonalSelectionError(str(error)) from error
    if supplied != binding["canonicalRoot"]:
        raise PersonalSelectionError("projectRoot must equal its canonical local path.")
    return supplied, binding


def _normalize_discovery(document: Any, *, allow_permission: bool = False) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise PersonalSelectionError("Selection discovery must be an object.")
    allowed = _DISCOVERY_KEYS | ({"permission"} if allow_permission else set())
    if set(document) != allowed:
        raise PersonalSelectionError("Selection discovery has unknown or missing fields.")
    if document.get("schemaVersion") != 1:
        raise PersonalSelectionError("Selection discovery schemaVersion must be exactly 1.")
    if document.get("discoveryComplete") is not True:
        raise PersonalSelectionError("Figma discovery is incomplete; absence has not been proven.")

    project_root, project_binding = _normalize_project_root(document.get("projectRoot"))
    target_display = _display_target(document.get("targetFigmaFile"))
    target_identity = _identity_target(document.get("targetFigmaFile"))
    raw_candidates = document.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise PersonalSelectionError("candidates must be a non-empty complete array.")

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_candidates):
        item = _require_exact_object(raw, _CANDIDATE_KEYS, f"candidates[{index}]")
        file_key = _require_text(item.get("fileKey"), f"candidates[{index}].fileKey")
        version = _require_text(item.get("version"), f"candidates[{index}].version")
        name = _require_text(item.get("name"), f"candidates[{index}].name")
        if file_key in seen or file_key == target_identity["fileKey"]:
            raise PersonalSelectionError("Candidate and target Figma file identities must be unique.")
        seen.add(file_key)
        if not isinstance(item.get("published"), bool):
            raise PersonalSelectionError(f"candidates[{index}].published must be a boolean.")
        decision = item.get("decision")
        if decision not in {"use", "do_not_use"}:
            raise PersonalSelectionError(
                f"candidates[{index}].decision must be exactly use or do_not_use."
            )
        if decision == "use" and item["published"] is not True:
            raise PersonalSelectionError("An unpublished Figma library cannot be selected.")
        candidates.append(
            {
                "fileKey": file_key,
                "version": version,
                "name": name,
                "published": item["published"],
                "decision": decision,
            }
        )
    candidates.sort(key=lambda item: item["fileKey"])
    selected = [item for item in candidates if item["decision"] == "use"]
    excluded = [item for item in candidates if item["decision"] == "do_not_use"]
    if not selected:
        raise PersonalSelectionError(
            "At least one published design-system library must be explicitly selected."
        )

    adapters = document.get("adapters")
    if not isinstance(adapters, dict) or any(
        not isinstance(key, str) or not isinstance(value, dict)
        for key, value in adapters.items()
    ):
        raise PersonalSelectionError("adapters must map adapter IDs to configuration objects.")
    catalog = document.get("catalog")
    if not isinstance(catalog, dict):
        raise PersonalSelectionError("catalog must be a canonical object.")
    if catalog.get("sourceAvailable") is not True:
        raise PersonalSelectionError("Selected Figma catalog source is unavailable.")
    if catalog.get("sourceComplete") is not True:
        raise PersonalSelectionError("Selected Figma catalog source is incomplete.")

    catalog_readback = _normalize_catalog_readback(
        document.get("catalogReadback"),
        catalog=catalog,
        selected=selected,
    )
    library_decisions = [
        {
            "fileKey": item["fileKey"],
            "version": item["version"],
            "published": item["published"],
            "decision": item["decision"],
        }
        for item in candidates
    ]
    identity_document = {
        "schemaVersion": 1,
        "projectRoot": project_root,
        "projectBindingDigest": sha256_digest(project_binding),
        "targetFigmaFile": target_identity,
        "libraryDecisions": library_decisions,
        "adaptersDigest": sha256_digest(adapters),
        "catalogInputDigest": sha256_digest(catalog),
        "catalogReadbackDigest": sha256_digest(catalog_readback),
    }
    return {
        "projectRoot": project_root,
        "projectBinding": project_binding,
        "targetDisplay": target_display,
        "targetIdentity": target_identity,
        "candidates": candidates,
        "selected": selected,
        "excluded": excluded,
        "libraryDecisions": library_decisions,
        "adapters": copy.deepcopy(adapters),
        "catalog": copy.deepcopy(catalog),
        "catalogInputDigest": identity_document["catalogInputDigest"],
        "catalogReadback": catalog_readback,
        "catalogReadbackDigest": identity_document["catalogReadbackDigest"],
        "adaptersDigest": identity_document["adaptersDigest"],
        "projectBindingDigest": identity_document["projectBindingDigest"],
        "discoveryDigest": sha256_digest(identity_document),
        "permission": copy.deepcopy(document.get("permission")),
    }


def _permission_binding(run_id: str, discovery: dict[str, Any]) -> dict[str, Any]:
    try:
        safe_run_id = validate_run_id(run_id)
    except (TypeError, ValueError) as error:
        raise PersonalSelectionError(str(error)) from error
    unsigned = {
        "schemaVersion": 1,
        "action": "apply_personal_selection",
        "authorityMode": "personal_local",
        "runId": safe_run_id,
        "policyDigest": EXPECTED_POLICY_SHA256,
        "projectRoot": discovery["projectRoot"],
        "projectBindingDigest": discovery["projectBindingDigest"],
        "targetFigmaFile": copy.deepcopy(discovery["targetIdentity"]),
        "libraryDecisions": copy.deepcopy(discovery["libraryDecisions"]),
        "catalogInputDigest": discovery["catalogInputDigest"],
        "catalogReadbackDigest": discovery["catalogReadbackDigest"],
        "adaptersDigest": discovery["adaptersDigest"],
    }
    return {**unsigned, "bindingDigest": sha256_digest(unsigned)}


def prepare_selection_preview(
    home: Path,
    *,
    run_id: str,
    discovery: Any,
) -> dict[str, Any]:
    """Validate and preview one exact selection without writing local state."""

    # Validate lexical storage containment without creating the home.
    _selection_path(home, run_id)
    normalized = _normalize_discovery(discovery)
    binding = _permission_binding(run_id, normalized)
    return {
        "status": "permission_required",
        "authorityMode": "personal_local",
        "runId": binding["runId"],
        "targetFigmaFile": copy.deepcopy(normalized["targetDisplay"]),
        "libraryChoices": copy.deepcopy(normalized["candidates"]),
        "selectedLibraryFileKeys": [item["fileKey"] for item in normalized["selected"]],
        "excludedLibraryFileKeys": [item["fileKey"] for item in normalized["excluded"]],
        "permissionRequired": True,
        "permissionBinding": binding,
        "nextAction": "request_personal_selection_permission",
    }


def _validate_permission(discovery: dict[str, Any]) -> dict[str, Any]:
    permission = _require_exact_object(
        discovery.get("permission"),
        _PERMISSION_KEYS,
        "permission",
    )
    if permission.get("granted") is not True:
        raise PersonalSelectionError("The exact personal selection was not granted by the user.")
    run_id = permission.get("runId")
    expected = _permission_binding(run_id, discovery)
    supplied = {key: copy.deepcopy(value) for key, value in permission.items() if key != "granted"}
    if supplied != expected:
        raise PersonalSelectionError(
            "Selection permission does not match the exact run, project, target, candidates, versions, or catalog."
        )
    return expected


def _profile_and_scope(discovery: dict[str, Any]) -> tuple[dict[str, Any], str]:
    # Names are display-only and therefore never enter this authority scope.
    scope = {
        "schemaVersion": 1,
        "selectedLibraryFileKeys": [item["fileKey"] for item in discovery["selected"]],
        "targetFigmaFileKey": discovery["targetIdentity"]["fileKey"],
        "adaptersDigest": discovery["adaptersDigest"],
    }
    selection_set_digest = sha256_digest(scope)
    profile_id = f"personal-{selection_set_digest[:40]}"
    profile = {
        "schemaVersion": 1,
        "profileId": profile_id,
        "displayName": "Personal Figma selection",
        "figma": {
            "allowlistedLibraryFiles": [
                {"fileKey": item["fileKey"]} for item in discovery["selected"]
            ],
            "allowlistedWorkingFiles": [
                {"fileKey": discovery["targetIdentity"]["fileKey"]}
            ],
        },
        "adapters": copy.deepcopy(discovery["adapters"]),
    }
    validate_profile_id(profile_id)
    return profile, selection_set_digest


def _personal_catalog(
    discovery: dict[str, Any],
    *,
    profile_id: str,
) -> dict[str, Any]:
    catalog = copy.deepcopy(discovery["catalog"])
    catalog.pop("approvalAttestation", None)
    catalog["profileId"] = profile_id
    selected_versions = {
        item["fileKey"]: item["version"] for item in discovery["selected"]
    }
    excluded_keys = {item["fileKey"] for item in discovery["excluded"]}
    token_provenance = catalog.get("tokenProvenance")
    if (
        not isinstance(token_provenance, dict)
        or set(token_provenance)
        != {"approval", "source", "sourceVersion", "published"}
        or token_provenance.get("approval") != "explicit"
        or token_provenance.get("published") is not True
    ):
        raise PersonalSelectionError(
            "Personal catalog tokens require exact published provenance."
        )
    token_source = token_provenance.get("source")
    if token_source not in selected_versions:
        raise PersonalSelectionError("Catalog tokens originate outside selected libraries.")
    if token_provenance.get("sourceVersion") != selected_versions[token_source]:
        raise PersonalSelectionError("Catalog token source version has drifted.")
    target = discovery["targetIdentity"]
    source_cut = catalog.get("sourceCut")
    if not isinstance(source_cut, dict) or not isinstance(source_cut.get("figmaFiles"), list):
        raise PersonalSelectionError("catalog.sourceCut.figmaFiles must be a complete array.")
    found: set[str] = set()
    filtered_files: list[dict[str, str]] = []
    for item in source_cut["figmaFiles"]:
        if not isinstance(item, dict) or set(item) != {"fileKey", "version"}:
            raise PersonalSelectionError("Catalog Figma sources need exact fileKey and version fields.")
        file_key = item.get("fileKey")
        version = item.get("version")
        if file_key in selected_versions:
            if version != selected_versions[file_key] or file_key in found:
                raise PersonalSelectionError("Selected catalog source versions are incomplete or ambiguous.")
            found.add(file_key)
            filtered_files.append({"fileKey": file_key, "version": version})
        elif file_key in excluded_keys:
            continue
        elif file_key == target["fileKey"]:
            if version != target["version"]:
                raise PersonalSelectionError("Target working-file source version has drifted.")
        else:
            raise PersonalSelectionError("Catalog contains a source outside the complete candidate inventory.")
    if found != set(selected_versions):
        raise PersonalSelectionError("Catalog does not version every selected design-system library.")
    filtered_files.append(copy.deepcopy(target))
    source_cut["figmaFiles"] = sorted(filtered_files, key=lambda item: item["fileKey"])
    source_cut.pop("catalogDigest", None)

    registry = catalog.get("registry")
    if not isinstance(registry, dict) or set(registry) != {"components", "icons"}:
        raise PersonalSelectionError("catalog.registry must contain components and icons arrays.")
    for kind in ("components", "icons"):
        items = registry[kind]
        if not isinstance(items, list):
            raise PersonalSelectionError(f"catalog.registry.{kind} must be an array.")
        kept: list[dict[str, Any]] = []
        for raw_asset in items:
            if not isinstance(raw_asset, dict) or not isinstance(raw_asset.get("figma"), dict):
                raise PersonalSelectionError("Catalog registry assets require exact Figma provenance.")
            file_key = raw_asset["figma"].get("fileKey")
            if file_key in excluded_keys:
                continue
            if file_key not in selected_versions:
                raise PersonalSelectionError("Catalog registry contains an asset outside selected libraries.")
            if raw_asset.get("sourceVersion") != selected_versions[file_key]:
                raise PersonalSelectionError("Catalog registry asset source version has drifted.")
            asset = copy.deepcopy(raw_asset)
            if "workingFileInstances" in asset:
                instances = asset["workingFileInstances"]
                if not isinstance(instances, list):
                    raise PersonalSelectionError("workingFileInstances must be an array.")
                for instance in instances:
                    if not isinstance(instance, dict) or instance.get("fileKey") != target["fileKey"]:
                        raise PersonalSelectionError(
                            "Working-instance evidence belongs to another or unknown target file."
                        )
                    if instance.get("sourceVersion") != target["version"]:
                        raise PersonalSelectionError("Working-instance target version has drifted.")
            kept.append(asset)
        registry[kind] = kept
    return catalog


def _read_task_selection(
    home: Path,
    run_id: str,
    *,
    missing_ok: bool,
) -> dict[str, Any] | None:
    normalized_home = home.expanduser().absolute()
    path = _selection_path(normalized_home, run_id)
    if not path.exists():
        if missing_ok:
            return None
        raise PersonalSelectionError(f"No personal design-system selection exists for run {run_id!r}.")
    try:
        if is_link_or_reparse(path):
            raise PersonalSelectionError("Personal selection evidence may not be redirected.")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise PersonalSelectionError("Personal selection evidence must be a regular file.")
        record = read_canonical_json(path)
        _require_exact_object(record, _SELECTION_KEYS, "personal selection record")
        unsigned = {key: copy.deepcopy(record[key]) for key in _SELECTION_UNSIGNED_KEYS}
        if record.get("selectionDigest") != sha256_digest(unsigned):
            raise PersonalSelectionError("Personal selection digest is invalid.")
        verify_authority_seal(
            normalized_home,
            f"{_SELECTION_PURPOSE_PREFIX}{run_id}",
            {**unsigned, "selectionDigest": record["selectionDigest"]},
            record.get("authoritySeal"),
        )
        if record.get("runId") != run_id or record.get("authorityMode") != "personal_local":
            raise PersonalSelectionError("Personal selection identity does not match its path.")
        if record.get("policyDigest") != verify_policy_anchor(normalized_home):
            raise PersonalSelectionError("Personal selection policy digest has drifted.")
        assert_guardian_storage_path(normalized_home, path)
    except PersonalSelectionError:
        raise
    except (AuthorityIntegrityError, OSError, PathIntegrityError, ValueError, UnicodeError) as error:
        raise PersonalSelectionError(f"Personal selection evidence is invalid: {error}") from error
    return copy.deepcopy(record)


def load_personal_profile_authority(
    home: Path,
    profile_id: str,
    *,
    missing_ok: bool = True,
) -> dict[str, Any] | None:
    """Load the sealed marker that makes a profile personal rather than enterprise."""

    try:
        from .policy import verify_personal_profile_authority_binding

        return verify_personal_profile_authority_binding(
            home.expanduser().absolute(),
            profile_id,
            missing_ok=missing_ok,
        )
    except ImportError as error:
        raise PersonalSelectionError("Personal authority support is unavailable.") from error


def load_task_selection(home: Path, profile_id: str, run_id: str) -> dict[str, Any]:
    """Load one sealed run selection and require its exact personal profile."""

    try:
        validate_profile_id(profile_id)
    except (TypeError, ValueError) as error:
        raise PersonalSelectionError(str(error)) from error
    record = _read_task_selection(home, run_id, missing_ok=False)
    assert record is not None
    if record.get("profileId") != profile_id:
        raise PersonalSelectionError("Task selection belongs to a different personal profile.")
    authority = load_personal_profile_authority(home, profile_id, missing_ok=False)
    if not isinstance(authority, dict):
        raise PersonalSelectionError("Personal profile authority evidence is missing.")
    if authority.get("profileDigest") != record.get("profileDigest"):
        raise PersonalSelectionError("Task selection profile digest differs from personal authority.")
    if authority.get("selectionSetDigest") != record.get("selectionSetDigest"):
        raise PersonalSelectionError("Task selection set differs from personal authority.")
    return record


def inspect_personal_selection(home: Path, *, run_id: str) -> dict[str, Any]:
    """Read selection status without creating or repairing any local state."""

    record = _read_task_selection(home, run_id, missing_ok=True)
    if record is None:
        return {
            "status": "selection_required",
            "authorityMode": "personal_local",
            "runId": validate_run_id(run_id),
            "permissionRequired": True,
            "nextAction": "selection_preview",
        }
    normalized_home = home.expanduser().absolute()
    try:
        profile_id = record.get("profileId")
        record = load_task_selection(normalized_home, profile_id, run_id)
        profile = load_profile(normalized_home, profile_id)
        if sha256_digest(profile) != record.get("profileDigest"):
            raise PersonalSelectionError(
                "Personal selection profile digest differs from the installed profile."
            )

        paths = GuardianPaths(normalized_home)
        current_pointer = assert_guardian_storage_path(
            normalized_home,
            paths.profile(profile_id) / "current-snapshot.json",
        )
        if is_link_or_reparse(current_pointer):
            raise PersonalSelectionError(
                "Current personal snapshot pointer may not be redirected."
            )
        try:
            pointer_metadata = current_pointer.lstat()
        except FileNotFoundError as error:
            raise PersonalSelectionError(
                "Current personal snapshot pointer is missing; status will not repair it."
            ) from error
        if not stat.S_ISREG(pointer_metadata.st_mode):
            raise PersonalSelectionError(
                "Current personal snapshot pointer must be a regular file."
            )

        snapshot = load_snapshot(
            normalized_home,
            profile_id,
            record.get("snapshotId"),
            recover_missing_current=False,
        )
        for field in ("snapshotId", "catalogDigest", "profileDigest", "policyDigest"):
            if snapshot.get(field) != record.get(field):
                raise PersonalSelectionError(
                    f"Personal selection {field} differs from its immutable snapshot."
                )
        assert_guardian_storage_path(normalized_home, current_pointer)
    except PersonalSelectionError:
        raise
    except (GuardianError, OSError, PathIntegrityError, ValueError, UnicodeError) as error:
        raise PersonalSelectionError(
            f"Personal selection dependencies are invalid: {error}"
        ) from error
    return {"status": "allowed", **record, "permissionRequired": False}


def _existing_retry(
    home: Path,
    *,
    run_id: str,
    permission_binding: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any] | None:
    existing = _read_task_selection(home, run_id, missing_ok=True)
    if existing is None:
        return None
    if (
        existing.get("permissionBindingDigest") != permission_binding["bindingDigest"]
        or existing.get("discoveryDigest") != discovery["discoveryDigest"]
    ):
        raise PersonalSelectionError(
            "This runId already has a different create-once design-system selection."
        )
    validated = inspect_personal_selection(home, run_id=run_id)
    validated_record = {
        key: copy.deepcopy(validated[key]) for key in _SELECTION_KEYS
    }
    if validated_record != existing:
        raise PersonalSelectionError(
            "Personal selection changed while its exact retry was being validated."
        )

    return {
        "status": "allowed",
        **existing,
        "localChangesPerformed": False,
    }


def apply_personal_selection(home: Path, request: Any) -> dict[str, Any]:
    """Apply one permission-bound personal selection using only host-local trust."""

    normalized_home = home.expanduser().absolute()
    discovery = _normalize_discovery(request, allow_permission=True)
    permission = _validate_permission(discovery)
    run_id = permission["runId"]
    _selection_path(normalized_home, run_id)
    retry = _existing_retry(
        normalized_home,
        run_id=run_id,
        permission_binding=permission,
        discovery=discovery,
    )
    if retry is not None:
        return retry

    profile, selection_set_digest = _profile_and_scope(discovery)
    profile_digest = sha256_digest(profile)
    catalog = _personal_catalog(discovery, profile_id=profile["profileId"])
    try:
        from .catalog_authority import create_personal_catalog_approval
        from .policy import (
            create_personal_profile_authority_binding,
            install_personal_policy_anchor,
        )

        install_personal_policy_anchor(normalized_home)
        policy_digest = verify_policy_anchor(normalized_home)
        install_profile(normalized_home, profile)
        create_personal_profile_authority_binding(
            normalized_home,
            profile_id=profile["profileId"],
            profile_digest=profile_digest,
            selection_set_digest=selection_set_digest,
        )
        approved_catalog = create_personal_catalog_approval(
            normalized_home,
            policy_digest=policy_digest,
            profile=profile,
            catalog=catalog,
        )
        snapshot = ingest_snapshot(normalized_home, profile, approved_catalog)
    except PersonalSelectionError:
        raise
    except (OSError, ValueError) as error:
        raise PersonalSelectionError(f"Personal selection could not be applied: {error}") from error

    unsigned = {
        "schemaVersion": 1,
        "authorityMode": "personal_local",
        "runId": run_id,
        "profileId": profile["profileId"],
        "profileDigest": profile_digest,
        "snapshotId": snapshot["snapshotId"],
        "catalogDigest": snapshot["catalogDigest"],
        "policyDigest": policy_digest,
        "projectBindingDigest": discovery["projectBindingDigest"],
        "targetFigmaFile": copy.deepcopy(discovery["targetIdentity"]),
        "libraryDecisions": copy.deepcopy(discovery["libraryDecisions"]),
        "selectedLibraryFileKeys": [item["fileKey"] for item in discovery["selected"]],
        "excludedLibraryFileKeys": [item["fileKey"] for item in discovery["excluded"]],
        "selectionSetDigest": selection_set_digest,
        "permissionBindingDigest": permission["bindingDigest"],
        "catalogReadbackDigest": discovery["catalogReadbackDigest"],
        "discoveryDigest": discovery["discoveryDigest"],
    }
    selection_digest = sha256_digest(unsigned)
    sealed_payload = {**unsigned, "selectionDigest": selection_digest}
    record = {
        **sealed_payload,
        "authoritySeal": authority_seal(
            normalized_home,
            f"{_SELECTION_PURPOSE_PREFIX}{run_id}",
            sealed_payload,
        ),
    }
    path = _selection_path(normalized_home, run_id)
    try:
        exclusive_write_json(normalized_home, path, record)
    except FileExistsError:
        existing = _read_task_selection(normalized_home, run_id, missing_ok=False)
        if existing != record:
            raise PersonalSelectionError(
                "This runId was concurrently sealed for a different design-system selection."
            )
    return {
        "status": "allowed",
        **record,
        "localChangesPerformed": True,
    }


__all__ = [
    "PersonalSelectionError",
    "apply_personal_selection",
    "inspect_personal_selection",
    "load_personal_profile_authority",
    "load_task_selection",
    "prepare_selection_preview",
    "personal_catalog_readback_digest",
]

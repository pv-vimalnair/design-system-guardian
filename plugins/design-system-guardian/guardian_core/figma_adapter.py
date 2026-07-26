"""Strict Figma read-back evidence normalization for Guardian audits.

This module does not connect to Figma and never accepts a visual or equal-value
match as approval. A host uses its existing Figma connection to run the fixed
collector contract, then this boundary verifies that observation against one
run pin and one authority-sealed snapshot.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .audit import AUDIT_CATEGORIES
from .canonical import canonical_json_bytes, sha256_digest
from .contracts import ExitCode
from .project_binding import ProjectBindingError, validate_project_binding


FIGMA_ADAPTER_VERSION = "0.1.0"
FIGMA_BINDING_EXTENSION = "guardian.figma"
_FIGMA_COLLECTOR_CONTRACT = {
    "adapter": "figma",
    "adapterVersion": FIGMA_ADAPTER_VERSION,
    "contract": "guardian-figma-plugin-api-readback",
    "contractVersion": 1,
    "evidenceSchema": "figma-observation-v1",
    "proofMethod": "figma_plugin_api_readback",
    "readOnly": True,
    "bindingFields": [
        "collectorDigest",
        "configDigest",
        "policyDigest",
        "profileId",
        "projectBindingDigest",
        "runId",
        "snapshotId",
        "sourceCutDigest",
    ],
    "collectorAuthority": "unprotected_caller_carried",
    "productCopyCollected": False,
}


class FigmaAdapterIntegrityError(ValueError):
    """Raised when Figma evidence is malformed, forged, replayed, or ambiguous."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


class FigmaAdapterSourceError(ValueError):
    """Raised when exact Figma source evidence is unavailable, incomplete, or stale."""

    exit_code = ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE

    def __init__(self, status: str, message: str):
        if status not in {"source_unavailable", "source_incomplete", "stale"}:
            raise ValueError("Figma source errors require an exact source status.")
        self.status = status
        super().__init__(message)


_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_TOP_KEYS = {
    "schemaVersion",
    "adapter",
    "adapterVersion",
    "status",
    "binding",
    "source",
    "document",
    "analysis",
    "observations",
}
_BINDING_KEYS = {
    "runId",
    "profileId",
    "policyDigest",
    "snapshotId",
    "sourceCutDigest",
    "projectBindingDigest",
    "configDigest",
    "collectorDigest",
}
_SOURCE_KEYS = {"state", "available", "complete"}
_DOCUMENT_KEYS = {"fileKey", "sourceVersion", "rootNodeIds"}
_ANALYSIS_KEYS = {
    "method",
    "complete",
    "assessedNodes",
    "totalNodes",
    "assessedFields",
    "totalFields",
}
_VARIABLE_KEYS = {
    "kind",
    "category",
    "nodeId",
    "field",
    "identity",
    "variableKey",
    "collectionKey",
    "resolvedType",
}
_STYLE_KEYS = {
    "kind",
    "category",
    "nodeId",
    "field",
    "identity",
    "styleKey",
    "styleType",
    "range",
}
_ASSET_KEYS = {
    "kind",
    "category",
    "nodeId",
    "field",
    "identity",
    "figmaInstance",
}
_RAW_KEYS = {
    "kind",
    "category",
    "nodeId",
    "field",
    "valueDigest",
    "inferredVariableKeys",
}
_UNASSESSED_KEYS = {"kind", "category", "nodeId", "field", "reason"}
_INSTANCE_KEYS = {
    "fileKey",
    "nodeId",
    "sourceVersion",
    "nodeType",
    "canonicalAssetKey",
    "remote",
    "variant",
    "properties",
    "unapprovedOverrideFields",
}
_VARIABLE_EXTENSION_KEYS = {
    "bindingType",
    "fileKey",
    "sourceVersion",
    "key",
    "collectionKey",
    "resolvedType",
}
_STYLE_EXTENSION_KEYS = {
    "bindingType",
    "fileKey",
    "sourceVersion",
    "key",
    "styleType",
}
_SOURCE_STATES = {
    "fresh",
    "offline_grace",
    "stale",
    "source_unavailable",
    "source_incomplete",
}
_OBSERVATION_STATUSES = {
    "allowed",
    "unsupported",
    "stale",
    "source_unavailable",
    "source_incomplete",
}
_STYLE_CATEGORIES = {
    "paint": "colors",
    "text": "typography",
    "effect": "effects",
    "grid": "spacing",
}
_TOKEN_CATEGORY_RULES = {
    "color": {"colors"},
    "fontFamily": {"typography"},
    "fontWeight": {"typography"},
    "typography": {"typography"},
    "duration": {"motion"},
    "cubicBezier": {"motion"},
    "transition": {"motion"},
    "shadow": {"effects"},
    "gradient": {"colors"},
    "dimension": {"spacing", "radii"},
    "number": {"spacing", "radii", "motion", "effects"},
    "strokeStyle": {"colors", "spacing"},
    "border": {"colors", "spacing", "radii"},
}


def _collector_digest() -> str:
    return sha256_digest(_FIGMA_COLLECTOR_CONTRACT)


def collector_digest() -> str:
    """Return the stable digest of the shipped read-only collector contract."""

    return _collector_digest()


def _exact_object(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise FigmaAdapterIntegrityError(f"{field} has unknown or missing fields.")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FigmaAdapterIntegrityError(f"{field} must be a non-empty string.")
    return value


def _digest(value: Any, field: str) -> str:
    text = _string(value, field)
    if not _HEX_64.fullmatch(text):
        raise FigmaAdapterIntegrityError(f"{field} must be a lowercase SHA-256 digest.")
    return text


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FigmaAdapterIntegrityError(f"{field} must be a non-negative integer.")
    return value


def _sorted_unique_strings(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise FigmaAdapterIntegrityError(f"{field} must be an exact string array.")
    if any(not isinstance(item, str) or not item for item in value):
        raise FigmaAdapterIntegrityError(f"{field} contains an invalid string.")
    if value != sorted(set(value)):
        raise FigmaAdapterIntegrityError(f"{field} must be sorted and unique.")
    return list(value)


def _validate_pin_and_snapshot(
    run_pin: Any, verified_snapshot: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(run_pin, dict) or run_pin.get("schemaVersion") != 1:
        raise FigmaAdapterIntegrityError("Figma normalization requires one verified run pin.")
    if not isinstance(verified_snapshot, dict):
        raise FigmaAdapterIntegrityError("Figma normalization requires one verified snapshot.")
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        _string(run_pin.get(field), f"run pin {field}")
    if not _PROFILE_ID.fullmatch(str(run_pin["profileId"])):
        raise FigmaAdapterIntegrityError("Run pin profileId is invalid.")
    for field in ("snapshotId", "policyDigest"):
        _digest(run_pin.get(field), f"run pin {field}")
    if not isinstance(run_pin.get("sourceCut"), dict):
        raise FigmaAdapterIntegrityError("Run pin sourceCut must be an object.")
    if run_pin.get("sourceState") not in _SOURCE_STATES:
        raise FigmaAdapterIntegrityError("Run pin sourceState is invalid.")
    try:
        validate_project_binding(run_pin.get("projectBinding"))
    except ProjectBindingError as error:
        raise FigmaAdapterIntegrityError(
            f"Run pin project binding is invalid: {error}"
        ) from error
    for field in ("profileId", "snapshotId", "policyDigest", "sourceCut"):
        if verified_snapshot.get(field) != run_pin.get(field):
            raise FigmaAdapterIntegrityError(
                f"Verified snapshot {field} differs from the run pin."
            )
    if not isinstance(verified_snapshot.get("tokens"), dict) or not isinstance(
        verified_snapshot.get("registry"), dict
    ):
        raise FigmaAdapterIntegrityError("Verified snapshot catalog shape is invalid.")
    return copy.deepcopy(run_pin), copy.deepcopy(verified_snapshot)


def _source_documents(source_cut: Mapping[str, Any]) -> dict[str, str]:
    figma_files = source_cut.get("figmaFiles")
    if not isinstance(figma_files, list) or not figma_files:
        raise FigmaAdapterIntegrityError("Source cut requires pinned Figma files.")
    output: dict[str, str] = {}
    for item in figma_files:
        if not isinstance(item, dict) or set(item) != {"fileKey", "version"}:
            raise FigmaAdapterIntegrityError("Pinned Figma file evidence is malformed.")
        file_key = _string(item.get("fileKey"), "sourceCut.fileKey")
        version = _string(item.get("version"), "sourceCut.version")
        if file_key in output:
            raise FigmaAdapterIntegrityError("Pinned Figma files must be unique.")
        output[file_key] = version
    return output


def _figma_token_binding(
    token_value: Any,
    *,
    documents: Mapping[str, str],
) -> dict[str, Any] | None:
    if not isinstance(token_value, dict):
        raise FigmaAdapterIntegrityError("Snapshot token evidence is malformed.")
    extensions = token_value.get("extensions")
    if not isinstance(extensions, dict):
        raise FigmaAdapterIntegrityError("Snapshot token extensions must be an object.")
    value = extensions.get(FIGMA_BINDING_EXTENSION)
    if value is None:
        raise FigmaAdapterSourceError(
            "source_incomplete",
            "Approved token lacks exact Figma variable or style binding metadata.",
        )
    if not isinstance(value, dict):
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma token binding metadata is malformed."
        )
    binding_type = value.get("bindingType")
    expected_keys = (
        _VARIABLE_EXTENSION_KEYS if binding_type == "variable" else _STYLE_EXTENSION_KEYS
        if binding_type == "style"
        else None
    )
    if expected_keys is None or set(value) != expected_keys:
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma token binding metadata is incomplete."
        )
    file_key = value.get("fileKey")
    source_version = value.get("sourceVersion")
    if (
        not isinstance(file_key, str)
        or not isinstance(source_version, str)
        or documents.get(file_key) != source_version
    ):
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma token binding is not pinned to the source cut."
        )
    for field in expected_keys - {"bindingType"}:
        _string(value.get(field), f"Figma token binding {field}")
    if binding_type == "style" and value.get("styleType") not in _STYLE_CATEGORIES:
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma style binding type is unsupported."
        )
    provenance = token_value.get("provenance")
    if (
        token_value.get("approved") is not True
        or not isinstance(provenance, dict)
        or provenance.get("approval") != "explicit"
        or provenance.get("published") is not True
    ):
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma token binding lacks explicit published approval."
        )
    return copy.deepcopy(value)


def _asset_config(snapshot: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    registry = snapshot.get("registry")
    if not isinstance(registry, dict):
        raise FigmaAdapterIntegrityError("Snapshot registry must be an object.")
    output: dict[str, Any] = {}
    working_mode = False
    for plural, category in (("components", "components"), ("icons", "icons")):
        values = registry.get(plural)
        if not isinstance(values, list):
            raise FigmaAdapterIntegrityError(f"Snapshot registry {plural} must be an array.")
        for value in values:
            if not isinstance(value, dict):
                raise FigmaAdapterIntegrityError("Snapshot asset evidence is malformed.")
            if value.get("approved") is not True or value.get("status") != "approved":
                continue
            identity = _string(value.get("identity"), "asset identity")
            if identity in output:
                raise FigmaAdapterIntegrityError(
                    "One Figma identity cannot resolve to multiple approved assets."
                )
            figma = value.get("figma")
            if (
                not isinstance(figma, dict)
                or figma.get("published") is not True
                or not isinstance(figma.get("assetKey"), str)
                or not figma["assetKey"]
            ):
                raise FigmaAdapterSourceError(
                    "source_incomplete", "Approved Figma asset identity is incomplete."
                )
            bindings = value.get("workingFileInstances", [])
            if not isinstance(bindings, list):
                raise FigmaAdapterIntegrityError("Working-instance evidence must be an array.")
            working_mode = working_mode or bool(bindings)
            output[identity] = {
                "category": category,
                "assetKey": figma["assetKey"],
                "fileKey": figma.get("fileKey"),
                "sourceVersion": value.get("sourceVersion"),
                "variants": copy.deepcopy(value.get("variants", [])),
                "properties": copy.deepcopy(value.get("properties", {})),
                "workingFileInstances": copy.deepcopy(bindings),
            }
    return output, working_mode


def build_figma_adapter_config(
    *,
    run_pin: dict[str, Any],
    verified_snapshot: dict[str, Any],
    collector_digest: str | None = None,
) -> dict[str, Any]:
    """Derive the exact collector allowlist from one sealed run and snapshot."""

    pin, snapshot = _validate_pin_and_snapshot(run_pin, verified_snapshot)
    expected_collector_digest = _collector_digest()
    if collector_digest is None:
        collector_digest = expected_collector_digest
    collector_digest = _digest(collector_digest, "collectorDigest")
    if collector_digest != expected_collector_digest:
        raise FigmaAdapterIntegrityError(
            "Figma evidence must use Guardian's shipped collector contract."
        )
    documents = _source_documents(pin["sourceCut"])
    token_bindings: dict[str, Any] = {}
    token_types: dict[str, str] = {}
    for identity, token_value in sorted(snapshot["tokens"].items()):
        _string(identity, "token identity")
        if not isinstance(token_value, dict) or token_value.get("identity") != identity:
            raise FigmaAdapterIntegrityError("Snapshot token identity is not canonical.")
        token_types[identity] = _string(token_value.get("type"), "token type")
        binding = _figma_token_binding(token_value, documents=documents)
        if binding is not None:
            token_bindings[identity] = binding
    assets, working_mode = _asset_config(snapshot)
    unsigned = {
        "schemaVersion": 1,
        "adapter": "figma",
        "adapterVersion": FIGMA_ADAPTER_VERSION,
        "runId": pin["runId"],
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "projectBindingDigest": sha256_digest(pin["projectBinding"]),
        "collectorDigest": collector_digest,
        "documents": dict(sorted(documents.items())),
        "tokenBindings": token_bindings,
        "tokenTypes": token_types,
        "assets": dict(sorted(assets.items())),
        "workingMode": working_mode,
    }
    return {**unsigned, "configDigest": sha256_digest(unsigned)}


def _validate_binding(
    value: Any,
    *,
    pin: Mapping[str, Any],
    config: Mapping[str, Any],
) -> dict[str, str]:
    binding = _exact_object(value, _BINDING_KEYS, "Figma observation binding")
    expected = {
        "runId": pin["runId"],
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "projectBindingDigest": sha256_digest(pin["projectBinding"]),
        "configDigest": config["configDigest"],
        "collectorDigest": config["collectorDigest"],
    }
    if binding != expected:
        raise FigmaAdapterIntegrityError(
            "Figma observation is not bound to the exact run, config, and collector."
        )
    return expected


def _validate_source(
    value: Any,
    *,
    status: str,
    pin: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    source = _exact_object(value, _SOURCE_KEYS, "Figma source evidence")
    if source.get("state") not in _SOURCE_STATES:
        raise FigmaAdapterIntegrityError("Figma source state is invalid.")
    if not isinstance(source.get("available"), bool) or not isinstance(
        source.get("complete"), bool
    ):
        raise FigmaAdapterIntegrityError("Figma source flags must be boolean.")
    snapshot_state = snapshot.get("sourceState", pin.get("sourceState"))
    if source["state"] != pin.get("sourceState") or source["state"] != snapshot_state:
        raise FigmaAdapterIntegrityError("Figma source state differs from the pinned snapshot.")
    if snapshot.get("sourceAvailable") is False or source["available"] is False:
        raise FigmaAdapterSourceError(
            "source_unavailable", "Figma source was unavailable; absence was not proved."
        )
    if snapshot.get("sourceComplete") is False or source["complete"] is False:
        raise FigmaAdapterSourceError(
            "source_incomplete", "Figma source evidence was incomplete; absence was not proved."
        )
    if source["state"] == "stale" or status == "stale":
        raise FigmaAdapterSourceError("stale", "Figma source evidence is stale.")
    if status in {"source_unavailable", "source_incomplete"}:
        raise FigmaAdapterSourceError(status, f"Figma collector reported {status}.")
    return copy.deepcopy(source)


def _validate_document(
    value: Any,
    *,
    documents: Mapping[str, str],
) -> dict[str, Any]:
    document = _exact_object(value, _DOCUMENT_KEYS, "Figma document evidence")
    file_key = _string(document.get("fileKey"), "document.fileKey")
    source_version = _string(document.get("sourceVersion"), "document.sourceVersion")
    roots = _sorted_unique_strings(
        document.get("rootNodeIds"), "document.rootNodeIds", allow_empty=False
    )
    if file_key not in documents:
        raise FigmaAdapterSourceError(
            "source_incomplete", "Observed Figma document is not in the pinned source cut."
        )
    if documents[file_key] != source_version:
        raise FigmaAdapterSourceError(
            "stale", "Observed Figma document version differs from the pinned source cut."
        )
    return {"fileKey": file_key, "sourceVersion": source_version, "rootNodeIds": roots}


def _validate_analysis(value: Any, *, status: str) -> dict[str, Any]:
    analysis = _exact_object(value, _ANALYSIS_KEYS, "Figma analysis evidence")
    if analysis.get("method") != "figma_plugin_api_readback" or not isinstance(
        analysis.get("complete"), bool
    ):
        raise FigmaAdapterIntegrityError("Figma analysis method or completeness is invalid.")
    normalized = {
        "method": "figma_plugin_api_readback",
        "complete": analysis["complete"],
        "assessedNodes": _integer(analysis.get("assessedNodes"), "analysis.assessedNodes"),
        "totalNodes": _integer(analysis.get("totalNodes"), "analysis.totalNodes"),
        "assessedFields": _integer(analysis.get("assessedFields"), "analysis.assessedFields"),
        "totalFields": _integer(analysis.get("totalFields"), "analysis.totalFields"),
    }
    if normalized["assessedNodes"] > normalized["totalNodes"] or normalized[
        "assessedFields"
    ] > normalized["totalFields"]:
        raise FigmaAdapterIntegrityError("Figma assessed counts cannot exceed totals.")
    complete = (
        normalized["complete"] is True
        and normalized["assessedNodes"] == normalized["totalNodes"]
        and normalized["assessedFields"] == normalized["totalFields"]
    )
    if status == "allowed" and not complete:
        raise FigmaAdapterIntegrityError("Allowed Figma evidence must have complete read-back coverage.")
    if status == "unsupported" and normalized["complete"] is True:
        raise FigmaAdapterIntegrityError("Unsupported Figma evidence cannot claim complete analysis.")
    return normalized


def _instance(value: Any) -> dict[str, Any]:
    item = _exact_object(value, _INSTANCE_KEYS, "Figma instance evidence")
    for field in ("fileKey", "nodeId", "sourceVersion", "canonicalAssetKey"):
        _string(item.get(field), f"figmaInstance.{field}")
    if item.get("nodeType") not in {"INSTANCE", "FRAME", "COMPONENT"}:
        raise FigmaAdapterIntegrityError("Figma instance nodeType is invalid.")
    if not isinstance(item.get("remote"), bool):
        raise FigmaAdapterIntegrityError("Figma instance remote flag must be boolean.")
    variant = item.get("variant")
    if variant is not None:
        _string(variant, "figmaInstance.variant")
    properties = item.get("properties")
    if not isinstance(properties, dict):
        raise FigmaAdapterIntegrityError("Figma instance properties must be an object.")
    for name, selected in properties.items():
        _string(name, "figmaInstance property name")
        _string(selected, "figmaInstance property value")
    _sorted_unique_strings(
        item.get("unapprovedOverrideFields"),
        "figmaInstance.unapprovedOverrideFields",
    )
    return copy.deepcopy(item)


def _range(value: Any) -> dict[str, int] | None:
    if value is None:
        return None
    item = _exact_object(value, {"start", "end"}, "Figma text range")
    start = _integer(item.get("start"), "range.start")
    end = _integer(item.get("end"), "range.end")
    if end <= start:
        raise FigmaAdapterIntegrityError("Figma text range end must be greater than start.")
    return {"start": start, "end": end}


def _observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FigmaAdapterIntegrityError("Figma observations must be objects.")
    kind = value.get("kind")
    keys = {
        "variable": _VARIABLE_KEYS,
        "style": _STYLE_KEYS,
        "asset": _ASSET_KEYS,
        "raw": _RAW_KEYS,
        "unassessed": _UNASSESSED_KEYS,
    }.get(kind)
    if keys is None:
        raise FigmaAdapterIntegrityError("Figma observation kind is unsupported.")
    item = _exact_object(value, keys, f"Figma {kind} observation")
    if item.get("category") not in AUDIT_CATEGORIES:
        raise FigmaAdapterIntegrityError("Figma observation category is invalid.")
    for field in ("nodeId", "field"):
        _string(item.get(field), f"observation.{field}")
    if kind in {"variable", "style", "asset"}:
        _string(item.get("identity"), "observation.identity")
    if kind == "variable":
        for field in ("variableKey", "collectionKey", "resolvedType"):
            _string(item.get(field), f"observation.{field}")
    elif kind == "style":
        _string(item.get("styleKey"), "observation.styleKey")
        if item.get("styleType") not in _STYLE_CATEGORIES:
            raise FigmaAdapterIntegrityError("Figma styleType is unsupported.")
        item = {**copy.deepcopy(item), "range": _range(item.get("range"))}
    elif kind == "asset":
        if item.get("field") != "instance" or item.get("category") not in {
            "components",
            "icons",
        }:
            raise FigmaAdapterIntegrityError("Figma asset observation lane is invalid.")
        item = {**copy.deepcopy(item), "figmaInstance": _instance(item.get("figmaInstance"))}
        if item["figmaInstance"]["nodeId"] != item["nodeId"]:
            raise FigmaAdapterIntegrityError("Figma asset locator nodeId is inconsistent.")
    elif kind == "raw":
        _digest(item.get("valueDigest"), "observation.valueDigest")
        _sorted_unique_strings(
            item.get("inferredVariableKeys"), "observation.inferredVariableKeys"
        )
    else:
        _string(item.get("reason"), "observation.reason")
    return copy.deepcopy(item)


def _diagnostic(
    item: Mapping[str, Any],
    *,
    reason: str,
    binding: Mapping[str, str],
) -> dict[str, Any]:
    messages = {
        "raw_value_not_bound": "Raw Figma value is not bound to an approved identity.",
        "inferred_match_is_not_binding": "An inferred equal-value match is not an approved binding.",
        "identity_not_approved": "Figma identity is not explicitly approved in the pinned snapshot.",
        "variable_binding_not_exact": "Figma variable binding does not match the approved stable identity.",
        "style_binding_not_exact": "Figma style binding does not match the approved stable identity.",
        "working_instance_not_exactly_signed": "Figma component instance does not match signed working-file evidence.",
        "component_binding_not_exact": "Figma component instance does not match the approved component identity.",
    }
    evidence = {
        "adapter": "figma",
        "proofMethod": "figma_plugin_api_readback",
        "reason": reason,
        "nodeId": item["nodeId"],
        "field": item["field"],
        "binding": dict(binding),
    }
    identity = item.get("identity")
    if isinstance(identity, str):
        evidence["claimedIdentity"] = identity
    if item.get("kind") == "raw":
        evidence["valueDigest"] = item["valueDigest"]
        evidence["inferredVariableKeys"] = list(item["inferredVariableKeys"])
    stable = {"category": item["category"], "reason": reason, "evidence": evidence}
    return {
        "diagnosticId": "figma-" + sha256_digest(stable)[:24],
        "category": item["category"],
        "kind": "violation",
        "message": messages[reason],
        "evidence": evidence,
    }


def _token_diagnostic(
    item: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    binding: Mapping[str, str],
) -> dict[str, Any] | None:
    identity = item["identity"]
    expected = config["tokenBindings"].get(identity)
    if expected is None:
        if identity in snapshot["tokens"]:
            raise FigmaAdapterSourceError(
                "source_incomplete",
                f"Approved token {identity!r} lacks exact Figma binding metadata.",
            )
        return _diagnostic(item, reason="identity_not_approved", binding=binding)
    token_type = config["tokenTypes"].get(identity)
    allowed_categories = _TOKEN_CATEGORY_RULES.get(token_type, set())
    if item["kind"] == "variable":
        observed = {
            "bindingType": "variable",
            "fileKey": expected.get("fileKey"),
            "sourceVersion": expected.get("sourceVersion"),
            "key": item["variableKey"],
            "collectionKey": item["collectionKey"],
            "resolvedType": item["resolvedType"],
        }
        if item["category"] not in allowed_categories or observed != expected:
            return _diagnostic(item, reason="variable_binding_not_exact", binding=binding)
    else:
        observed = {
            "bindingType": "style",
            "fileKey": expected.get("fileKey"),
            "sourceVersion": expected.get("sourceVersion"),
            "key": item["styleKey"],
            "styleType": item["styleType"],
        }
        if (
            _STYLE_CATEGORIES[item["styleType"]] != item["category"]
            or item["category"] not in allowed_categories
            or observed != expected
        ):
            return _diagnostic(item, reason="style_binding_not_exact", binding=binding)
    return None


def _canonical_asset_is_exact(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    document: Mapping[str, Any],
) -> bool:
    if (
        observed.get("nodeType") != "INSTANCE"
        or observed.get("canonicalAssetKey") != expected.get("assetKey")
        or observed.get("unapprovedOverrideFields") != []
        or observed.get("fileKey") != document.get("fileKey")
        or observed.get("sourceVersion") != document.get("sourceVersion")
    ):
        return False
    variants = expected.get("variants", [])
    if variants:
        if observed.get("variant") not in variants:
            return False
    elif observed.get("variant") is not None:
        return False
    properties = expected.get("properties", {})
    selected = observed.get("properties")
    if not isinstance(properties, dict) or not isinstance(selected, dict):
        return False
    if set(properties) != set(selected):
        return False
    if any(selected[name] not in values for name, values in properties.items()):
        return False
    library_file = expected.get("fileKey")
    if document.get("fileKey") != library_file and observed.get("remote") is not True:
        return False
    return True


def _asset_diagnostic(
    item: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    document: Mapping[str, Any],
    binding: Mapping[str, str],
) -> dict[str, Any] | None:
    expected = config["assets"].get(item["identity"])
    if expected is None or expected.get("category") != item["category"]:
        return _diagnostic(item, reason="identity_not_approved", binding=binding)
    observed = item["figmaInstance"]
    working_file_keys = {
        signed.get("fileKey")
        for asset in config["assets"].values()
        for signed in asset.get("workingFileInstances", [])
        if isinstance(signed, dict)
    }
    if document.get("fileKey") in working_file_keys:
        if observed not in expected.get("workingFileInstances", []):
            return _diagnostic(
                item, reason="working_instance_not_exactly_signed", binding=binding
            )
    elif not _canonical_asset_is_exact(observed, expected, document=document):
        return _diagnostic(item, reason="component_binding_not_exact", binding=binding)
    return None


def normalize_figma_observation(
    value: Any,
    *,
    run_pin: dict[str, Any],
    verified_snapshot: dict[str, Any],
    collector_digest: str | None = None,
) -> dict[str, Any]:
    """Validate fixed Figma read-back evidence and project audit.py's contract."""

    raw = _exact_object(value, _TOP_KEYS, "Figma observation")
    if (
        raw.get("schemaVersion") != 1
        or raw.get("adapter") != "figma"
        or raw.get("adapterVersion") != FIGMA_ADAPTER_VERSION
    ):
        raise FigmaAdapterIntegrityError("Figma observation schema or adapter version is unsupported.")
    status = raw.get("status")
    if status not in _OBSERVATION_STATUSES:
        raise FigmaAdapterIntegrityError("Figma observation status is invalid.")
    pin, snapshot = _validate_pin_and_snapshot(run_pin, verified_snapshot)
    config = build_figma_adapter_config(
        run_pin=pin,
        verified_snapshot=snapshot,
        collector_digest=collector_digest,
    )
    binding = _validate_binding(raw.get("binding"), pin=pin, config=config)
    _validate_source(
        raw.get("source"), status=status, pin=pin, snapshot=snapshot
    )
    document = _validate_document(raw.get("document"), documents=config["documents"])
    analysis = _validate_analysis(raw.get("analysis"), status=status)

    if not isinstance(raw.get("observations"), list):
        raise FigmaAdapterIntegrityError("Figma observations must be an array.")
    observations = [_observation(item) for item in raw["observations"]]
    if observations != sorted(observations, key=canonical_json_bytes):
        raise FigmaAdapterIntegrityError("Figma observations must be in canonical order.")
    observation_keys: set[bytes] = set()
    for item in observations:
        locator = canonical_json_bytes(
            {
                "nodeId": item["nodeId"],
                "category": item["category"],
                "field": item["field"],
                "range": item.get("range"),
            }
        )
        if locator in observation_keys:
            raise FigmaAdapterIntegrityError(
                "One Figma node field cannot carry duplicate observations."
            )
        observation_keys.add(locator)
    if status == "unsupported":
        if observations:
            raise FigmaAdapterIntegrityError("Unsupported Figma evidence cannot carry observations.")
        categories = {
            category: {"status": "unsupported", "assessedItems": 0, "totalItems": 0}
            for category in AUDIT_CATEGORIES
        }
        return {
            "schemaVersion": 1,
            "adapter": "figma",
            "supported": False,
            "configDigest": config["configDigest"],
            "sourceCut": copy.deepcopy(pin["sourceCut"]),
            "assessedFiles": analysis["assessedNodes"],
            "totalFiles": analysis["totalNodes"],
            "categories": categories,
            "diagnostics": [],
        }

    if len(observations) != analysis["assessedFields"]:
        raise FigmaAdapterIntegrityError(
            "Figma observation count differs from assessed field evidence."
        )
    distinct_nodes = {item["nodeId"] for item in observations}
    if len(distinct_nodes) != analysis["assessedNodes"]:
        raise FigmaAdapterIntegrityError(
            "Figma observed node count differs from assessed node evidence."
        )

    diagnostics: list[dict[str, Any]] = []
    totals = {category: 0 for category in AUDIT_CATEGORIES}
    assessed = {category: 0 for category in AUDIT_CATEGORIES}
    for item in observations:
        category = item["category"]
        totals[category] += 1
        if item["kind"] == "unassessed":
            continue
        assessed[category] += 1
        diagnostic: dict[str, Any] | None = None
        if item["kind"] == "raw":
            reason = (
                "inferred_match_is_not_binding"
                if item["inferredVariableKeys"]
                else "raw_value_not_bound"
            )
            diagnostic = _diagnostic(item, reason=reason, binding=binding)
        elif item["kind"] in {"variable", "style"}:
            diagnostic = _token_diagnostic(
                item, config=config, snapshot=snapshot, binding=binding
            )
        elif item["kind"] == "asset":
            diagnostic = _asset_diagnostic(
                item, config=config, document=document, binding=binding
            )
        if diagnostic is not None:
            diagnostics.append(diagnostic)

    categories = {
        category: {
            # v0.3.3 has no protected receipt proving that the shipped
            # collector, rather than its caller, produced this evidence.
            # Preserve exact diagnostics, but never turn clean caller-carried
            # observations into an allowed coverage claim.
            "status": "not_assessed",
            "assessedItems": assessed[category],
            "totalItems": totals[category],
        }
        for category in AUDIT_CATEGORIES
    }
    diagnostics = sorted(diagnostics, key=canonical_json_bytes)
    diagnostic_ids = [item["diagnosticId"] for item in diagnostics]
    if len(diagnostic_ids) != len(set(diagnostic_ids)):
        raise FigmaAdapterIntegrityError("Normalized Figma diagnostic IDs collide.")
    return {
        "schemaVersion": 1,
        "adapter": "figma",
        "supported": True,
        "configDigest": config["configDigest"],
        "sourceCut": copy.deepcopy(pin["sourceCut"]),
        "assessedFiles": analysis["assessedNodes"],
        "totalFiles": analysis["totalNodes"],
        "categories": categories,
        "diagnostics": diagnostics,
    }


def expected_figma_ux_target(
    value: Any,
    *,
    run_pin: dict[str, Any],
    verified_snapshot: dict[str, Any],
    collector_digest: str | None = None,
) -> dict[str, Any]:
    """Derive the exact run-bound UX target from validated Figma evidence.

    The target identifies the observed document roots; it does not turn
    caller-carried collector evidence into protected authority.
    """

    normalize_figma_observation(
        value,
        run_pin=run_pin,
        verified_snapshot=verified_snapshot,
        collector_digest=collector_digest,
    )
    config = build_figma_adapter_config(
        run_pin=run_pin,
        verified_snapshot=verified_snapshot,
        collector_digest=collector_digest,
    )
    document = {
        "fileKey": value["document"]["fileKey"],
        "sourceVersion": value["document"]["sourceVersion"],
    }
    screen_digests = [
        sha256_digest(
            {
                "kind": "figma_screen",
                "runId": config["runId"],
                "projectBindingDigest": config["projectBindingDigest"],
                "configDigest": config["configDigest"],
                "document": document,
                "rootNodeId": root_node_id,
            }
        )
        for root_node_id in value["document"]["rootNodeIds"]
    ]
    return {
        "flowDigest": sha256_digest(
            {
                "kind": "figma_flow",
                "runId": config["runId"],
                "projectBindingDigest": config["projectBindingDigest"],
                "configDigest": config["configDigest"],
                "document": document,
                "screenDigests": screen_digests,
            }
        ),
        "screenDigests": screen_digests,
    }


__all__ = [
    "FIGMA_ADAPTER_VERSION",
    "FIGMA_BINDING_EXTENSION",
    "FigmaAdapterIntegrityError",
    "FigmaAdapterSourceError",
    "build_figma_adapter_config",
    "collector_digest",
    "expected_figma_ux_target",
    "normalize_figma_observation",
]

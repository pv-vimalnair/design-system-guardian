"""Canonical diagnostic sentinel manifest and generation."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, decode_json_bytes, sha256_digest


EXPECTED_SENTINEL_MANIFEST_SHA256 = "1d3b85234caa4478879733b74f1bde2cf1d6aed195737e575b826b06867cf69c"
_EXPECTED_KEYS = {
    "schemaVersion", "namespace", "productionReady", "automaticPromotion", "style", "kinds"
}
_EXPECTED_STYLE_KEYS = {"background", "foreground", "border", "pattern"}
_EXPECTED_KINDS = {"icon", "color", "textStyle", "component", "token"}
_SENTINEL_KEYS = {
    "schemaVersion", "namespace", "manifestDigest", "assetId", "kind",
    "label", "requestId", "policyDigest", "diagnosticStyle",
    "productionReady", "automaticPromotion",
}


class SentinelIntegrityError(ValueError):
    """Raised when fixed sentinel infrastructure drifts from its sealed contract."""


def sentinel_manifest_path() -> Path:
    return Path(__file__).resolve().parents[1] / "sentinels" / "manifest.json"


def load_sentinel_manifest() -> dict[str, Any]:
    try:
        payload = sentinel_manifest_path().read_bytes()
        manifest = decode_json_bytes(payload)
        canonical = canonical_json_bytes(manifest)
        if payload not in {canonical + b"\n", canonical + b"\r\n"}:
            raise ValueError("manifest bytes are not canonical JSON plus one terminal line ending")
    except (OSError, ValueError, UnicodeError) as error:
        raise SentinelIntegrityError(f"Sentinel manifest cannot be read canonically: {error}") from error
    if not isinstance(manifest, dict) or set(manifest) != _EXPECTED_KEYS:
        raise SentinelIntegrityError("Sentinel manifest has an invalid top-level contract.")
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("namespace") != "design_system_guardian.sentinel.v1"
        or manifest.get("productionReady") is not False
        or manifest.get("automaticPromotion") is not False
        or not isinstance(manifest.get("style"), dict)
        or set(manifest["style"]) != _EXPECTED_STYLE_KEYS
        or not isinstance(manifest.get("kinds"), dict)
        or set(manifest["kinds"]) != _EXPECTED_KINDS
        or any(not isinstance(value, str) or not value for value in manifest["style"].values())
        or any(not isinstance(value, str) or not value for value in manifest["kinds"].values())
    ):
        raise SentinelIntegrityError("Sentinel manifest differs from its fixed diagnostic contract.")
    if sha256_digest(manifest) != EXPECTED_SENTINEL_MANIFEST_SHA256:
        raise SentinelIntegrityError("Sentinel manifest digest differs from the compiled contract.")
    return copy.deepcopy(manifest)


def make_sentinel(*, kind: str, request_id: str, policy_digest: str) -> dict[str, Any]:
    manifest = load_sentinel_manifest()
    if kind not in manifest["kinds"]:
        raise SentinelIntegrityError(f"Unknown sentinel kind: {kind!r}.")
    return {
        "schemaVersion": manifest["schemaVersion"],
        "namespace": manifest["namespace"],
        "manifestDigest": EXPECTED_SENTINEL_MANIFEST_SHA256,
        "assetId": f"design_system_guardian.sentinel.{kind}.v1",
        "kind": kind,
        "label": manifest["kinds"][kind],
        "requestId": request_id,
        "policyDigest": policy_digest,
        "diagnosticStyle": copy.deepcopy(manifest["style"]),
        "productionReady": manifest["productionReady"],
        "automaticPromotion": manifest["automaticPromotion"],
    }

def validate_sentinel(value: Any, *, policy_digest: str) -> dict[str, Any]:
    """Reconstruct and compare every fixed sentinel field; visual similarity is irrelevant."""

    if not isinstance(value, dict) or set(value) != _SENTINEL_KEYS:
        raise SentinelIntegrityError("Sentinel has unknown or missing fields.")
    kind = value.get("kind")
    request_id = value.get("requestId")
    if not isinstance(kind, str) or not isinstance(request_id, str) or not request_id:
        raise SentinelIntegrityError("Sentinel kind and requestId must be exact non-empty strings.")
    expected = make_sentinel(kind=kind, request_id=request_id, policy_digest=policy_digest)
    if value != expected:
        raise SentinelIntegrityError("Sentinel differs from the fixed diagnostic contract.")
    return copy.deepcopy(expected)

"""Externally authorized, append-only Guardian release lifecycle.

Production code in this module verifies Ed25519 signatures only. The designated
authority's private key remains outside Guardian, Codex, and the plugin cache.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import importlib
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .authority import AuthorityIntegrityError, authority_seal, verify_authority_seal
from .canonical import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    read_canonical_json,
    sha256_digest,
)
from .catalog_authority import (
    CatalogAuthorityError,
    read_catalog_authority_public_key,
    verify_pinned_catalog_authority,
    verify_runtime_dependency,
)
from .clock import utc_now as _utc_now
from .contracts import ExitCode
from .paths import (
    PathIntegrityError,
    assert_guardian_storage_path,
    default_guardian_home,
    is_link_or_reparse,
)
from .policy import EXPECTED_POLICY_SHA256, verify_policy_anchor
from .storage import contained_atomic_write_json


PLUGIN_NAME = "design-system-guardian"
RUNTIME_VERSION = "0.3.5"
CURRENT_RELEASE_SCHEMA_VERSION = 1
SUPPORTED_RELEASE_SCHEMA_VERSIONS = frozenset({1})
CURRENT_STATE_SCHEMA_VERSION = 1
SUPPORTED_STATE_SCHEMA_VERSIONS = frozenset({1})
RELEASE_SIGNING_DOMAIN = "design-system-guardian.release-manifest.v1"
RELEASE_AUTHORITY_BINDING_PURPOSE = "release-authority-binding:v1"
_CHANNELS = frozenset({"canary", "stable"})
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_FULL_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CANONICAL_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_MANIFEST_KEYS = {
    "schemaVersion",
    "manifestType",
    "pluginName",
    "pluginVersion",
    "channel",
    "channelSequence",
    "sourceCommit",
    "artifactDigest",
    "policyDigest",
    "stateSchemaVersion",
    "runtimeCompatibility",
    "issuedAt",
    "targetManifestDigest",
    "reason",
    "authority",
}
_AUTHORITY_KEYS = {"schemaVersion", "algorithm", "keyId", "signature"}
_AUTHORITY_METADATA_KEYS = {"schemaVersion", "algorithm", "keyId"}
_COMPATIBILITY_KEYS = {"minimumVersion", "maximumVersionExclusive"}
_BINDING_KEYS = {
    "schemaVersion",
    "algorithm",
    "keyId",
    "publicKeyDigest",
    "policyDigest",
    "purpose",
    "authoritySeal",
}
_STATE_KEYS = {
    "schemaVersion",
    "channel",
    "channelSequence",
    "actionManifestDigest",
    "activeManifestDigest",
    "pluginVersion",
    "sourceCommit",
    "artifactDigest",
    "policyDigest",
    "canaryEvidenceDigest",
    "eventRecordedAt",
    "activatedAt",
    "authoritySeal",
}
_HISTORY_KEYS = {
    "schemaVersion",
    "recordType",
    "eventId",
    "channel",
    "channelSequence",
    "actionManifestDigest",
    "activeManifestDigest",
    "previousActiveManifestDigest",
    "pluginVersion",
    "sourceCommit",
    "artifactDigest",
    "policyDigest",
    "canaryEvidenceDigest",
    "authorityKeyId",
    "recordedAt",
    "authoritySeal",
}


class ReleaseIntegrityError(ValueError):
    """Fail-closed release authority, manifest, or ledger error."""

    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY


@dataclass(frozen=True)
class ReleaseResult:
    channel: str
    record_type: str
    action_manifest_digest: str
    active_manifest_digest: str
    history_path: Path
    state_path: Path


def _normalized_home(home: Path) -> Path:
    value = home.expanduser().absolute()
    try:
        assert_guardian_storage_path(value, value)
    except PathIntegrityError as error:
        raise ReleaseIntegrityError(str(error)) from error
    return value


def _authority_root(home: Path) -> Path:
    return assert_guardian_storage_path(home, home / "trust" / "release-authority-v1")


def _release_root(home: Path) -> Path:
    return assert_guardian_storage_path(home, home / "releases")


def _manifest_path(home: Path, digest: str) -> Path:
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise ReleaseIntegrityError("Release manifest digest must be exact lowercase SHA-256.")
    return assert_guardian_storage_path(
        home, _release_root(home) / "manifests" / f"{digest}.json"
    )


def _artifact_path(home: Path, digest: str) -> Path:
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise ReleaseIntegrityError("Release artifact digest must be exact lowercase SHA-256.")
    return assert_guardian_storage_path(
        home, _release_root(home) / "artifacts" / f"{digest}.plugin"
    )


def _binding_unsigned(canonical_pem: bytes, key_id: str, policy_digest: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "keyId": key_id,
        "publicKeyDigest": hashlib.sha256(canonical_pem).hexdigest(),
        "policyDigest": policy_digest,
        "purpose": "canonical-release-authority",
    }


def _enroll_release_authority_at_home(home: Path, public_key_path: Path) -> str:
    """Pin one externally held Ed25519 release authority; never replace it."""

    normalized_home = _normalized_home(home)
    try:
        policy_digest = verify_policy_anchor(normalized_home)
        canonical_pem, key_id = read_catalog_authority_public_key(public_key_path)
        _, catalog_key_id = verify_pinned_catalog_authority(normalized_home)
        if key_id == catalog_key_id:
            raise ReleaseIntegrityError(
                "Release and catalog approval authorities must use distinct Ed25519 keys."
            )
        root = _authority_root(normalized_home)
        if root.exists():
            _, pinned_key_id = _verify_pinned_release_authority_at_home(normalized_home)
            if pinned_key_id != key_id:
                raise ReleaseIntegrityError(
                    "The create-once release authority cannot be replaced by another key."
                )
            return key_id
        trust = assert_guardian_storage_path(normalized_home, normalized_home / "trust")
        trust.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".release-authority.", dir=trust))
        promoted = False
        try:
            unsigned = _binding_unsigned(canonical_pem, key_id, policy_digest)
            atomic_write_bytes(stage / "public-key.pem", canonical_pem)
            atomic_write_json(
                stage / "binding.json",
                {
                    **unsigned,
                    "authoritySeal": authority_seal(
                        normalized_home,
                        RELEASE_AUTHORITY_BINDING_PURPOSE,
                        unsigned,
                    ),
                },
            )
            try:
                os.rename(stage, root)
                promoted = True
            except OSError:
                if root.exists():
                    _, pinned_key_id = _verify_pinned_release_authority_at_home(normalized_home)
                    if pinned_key_id != key_id:
                        raise ReleaseIntegrityError(
                            "Concurrent enrollment pinned a different release authority."
                        )
                    return key_id
                raise
        finally:
            if not promoted and stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
        _, verified_key_id = _verify_pinned_release_authority_at_home(normalized_home)
        return verified_key_id
    except ReleaseIntegrityError:
        raise
    except (AuthorityIntegrityError, CatalogAuthorityError, PathIntegrityError) as error:
        raise ReleaseIntegrityError(f"Release authority enrollment failed: {error}") from error
    except OSError as error:
        raise ReleaseIntegrityError(f"Release authority enrollment failed: {error}") from error


def _verify_pinned_release_authority_at_home(home: Path) -> tuple[Any, str]:
    """Verify the public key and host seal for the designated release authority."""

    normalized_home = _normalized_home(home)
    try:
        policy_digest = verify_policy_anchor(normalized_home)
        root = _authority_root(normalized_home)
        key_path = assert_guardian_storage_path(normalized_home, root / "public-key.pem")
        binding_path = assert_guardian_storage_path(normalized_home, root / "binding.json")
        for path in (root, key_path, binding_path):
            if is_link_or_reparse(path):
                raise ReleaseIntegrityError("Release authority evidence may not be redirected.")
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ReleaseIntegrityError("Release authority root must be a directory.")
        if not stat.S_ISREG(key_path.lstat().st_mode) or not stat.S_ISREG(
            binding_path.lstat().st_mode
        ):
            raise ReleaseIntegrityError("Release authority evidence must use regular files.")
        canonical_pem, key_id = read_catalog_authority_public_key(key_path)
        _, catalog_key_id = verify_pinned_catalog_authority(normalized_home)
        if key_id == catalog_key_id:
            raise ReleaseIntegrityError(
                "Release and catalog approval authorities must use distinct Ed25519 keys."
            )
        if key_path.read_bytes() != canonical_pem:
            raise ReleaseIntegrityError("Release authority public key is not canonical PEM.")
        binding = read_canonical_json(binding_path)
        if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
            raise ReleaseIntegrityError("Release authority binding has an invalid exact contract.")
        if type(binding.get("schemaVersion")) is not int or binding["schemaVersion"] != 1:
            raise ReleaseIntegrityError(
                "Release authority binding schemaVersion must be the exact integer 1."
            )
        unsigned = {key: value for key, value in binding.items() if key != "authoritySeal"}
        if unsigned != _binding_unsigned(canonical_pem, key_id, policy_digest):
            raise ReleaseIntegrityError(
                "Release authority differs from its create-once host binding."
            )
        verify_authority_seal(
            normalized_home,
            RELEASE_AUTHORITY_BINDING_PURPOSE,
            unsigned,
            binding["authoritySeal"],
        )
        verify_runtime_dependency()
        serialization = importlib.import_module("cryptography.hazmat.primitives.serialization")
        asymmetric = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")
        public_key = serialization.load_pem_public_key(canonical_pem)
        if not isinstance(public_key, asymmetric.Ed25519PublicKey):
            raise ReleaseIntegrityError("Release authority public key must be Ed25519.")
        return public_key, key_id
    except ReleaseIntegrityError:
        raise
    except (AuthorityIntegrityError, CatalogAuthorityError, PathIntegrityError) as error:
        raise ReleaseIntegrityError(f"Pinned release authority is invalid: {error}") from error
    except (OSError, ValueError, UnicodeError, ImportError, AttributeError) as error:
        raise ReleaseIntegrityError(f"Pinned release authority is invalid: {error}") from error


def _parse_semver(value: Any, field: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    if not isinstance(value, str):
        raise ReleaseIntegrityError(f"{field} must be strict SemVer.")
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise ReleaseIntegrityError(f"{field} must be strict SemVer.")
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease


def _compare_semver(left: str, right: str) -> int:
    left_value = _parse_semver(left, "pluginVersion")
    right_value = _parse_semver(right, "pluginVersion")
    for left_part, right_part in zip(left_value[:3], right_value[:3]):
        if left_part != right_part:
            return 1 if left_part > right_part else -1
    left_pre, right_pre = left_value[3], right_value[3]
    if left_pre is None or right_pre is None:
        if left_pre == right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_id, right_id in zip(left_pre, right_pre):
        if left_id == right_id:
            continue
        left_numeric, right_numeric = left_id.isdigit(), right_id.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_id) > int(right_id) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_id > right_id else -1
    if len(left_pre) == len(right_pre):
        return 0
    return 1 if len(left_pre) > len(right_pre) else -1


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not _CANONICAL_TIMESTAMP.fullmatch(value):
        raise ReleaseIntegrityError(f"{field} must be a canonical UTC ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseIntegrityError(f"{field} is not a valid timestamp.") from error
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")



def _positive_sequence(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > (1 << 63) - 1
    ):
        raise ReleaseIntegrityError("channelSequence must be a positive signed 64-bit integer.")
    return value


def _validate_manifest_contract(
    manifest: Any,
    *,
    require_signature: bool = True,
    enforce_activation: bool = True,
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise ReleaseIntegrityError("Release manifest has unknown or missing fields.")
    release_schema = manifest.get("schemaVersion")
    if (
        isinstance(release_schema, bool)
        or not isinstance(release_schema, int)
        or release_schema not in SUPPORTED_RELEASE_SCHEMA_VERSIONS
    ):
        raise ReleaseIntegrityError("Unsupported or future release manifest schemaVersion.")
    if enforce_activation and release_schema != CURRENT_RELEASE_SCHEMA_VERSION:
        raise ReleaseIntegrityError(
            "Candidate release manifest schemaVersion is not current for activation."
        )
    if manifest.get("pluginName") != PLUGIN_NAME:
        raise ReleaseIntegrityError("Release manifest targets another plugin.")
    version = manifest.get("pluginVersion")
    parsed_version = _parse_semver(version, "pluginVersion")
    channel = manifest.get("channel")
    if channel not in _CHANNELS:
        raise ReleaseIntegrityError("Release channel must be exactly canary or stable.")
    if channel == "stable" and parsed_version[3] is not None:
        raise ReleaseIntegrityError("Stable releases may not use a prerelease SemVer.")
    _positive_sequence(manifest.get("channelSequence"))
    if not isinstance(manifest.get("sourceCommit"), str) or not _FULL_COMMIT.fullmatch(
        manifest["sourceCommit"]
    ):
        raise ReleaseIntegrityError("sourceCommit must be one full 40- or 64-character Git object ID.")
    for field in ("artifactDigest", "policyDigest"):
        if not isinstance(manifest.get(field), str) or not _HEX_64.fullmatch(manifest[field]):
            raise ReleaseIntegrityError(f"{field} must be exact lowercase SHA-256.")
    if manifest["policyDigest"] != EXPECTED_POLICY_SHA256:
        raise ReleaseIntegrityError("Release manifest changed the immutable policy digest.")
    state_schema = manifest.get("stateSchemaVersion")
    if isinstance(state_schema, bool) or not isinstance(state_schema, int):
        raise ReleaseIntegrityError("stateSchemaVersion must be an integer.")
    if state_schema not in SUPPORTED_STATE_SCHEMA_VERSIONS:
        raise ReleaseIntegrityError("Unsupported or future Guardian state schemaVersion.")
    if enforce_activation and state_schema != CURRENT_STATE_SCHEMA_VERSION:
        raise ReleaseIntegrityError(
            "Candidate Guardian state schemaVersion is not current for activation."
        )
    compatibility = manifest.get("runtimeCompatibility")
    if not isinstance(compatibility, dict) or set(compatibility) != _COMPATIBILITY_KEYS:
        raise ReleaseIntegrityError("runtimeCompatibility has an invalid exact contract.")
    minimum = compatibility.get("minimumVersion")
    maximum = compatibility.get("maximumVersionExclusive")
    _parse_semver(minimum, "runtimeCompatibility.minimumVersion")
    _parse_semver(maximum, "runtimeCompatibility.maximumVersionExclusive")
    if _compare_semver(minimum, maximum) >= 0:
        raise ReleaseIntegrityError("Guardian runtime compatibility range is empty.")
    if enforce_activation and (
        _compare_semver(RUNTIME_VERSION, minimum) < 0
        or _compare_semver(RUNTIME_VERSION, maximum) >= 0
    ):
        raise ReleaseIntegrityError("This Guardian runtime is outside the signed compatibility range.")
    _parse_timestamp(manifest.get("issuedAt"), "issuedAt")
    manifest_type = manifest.get("manifestType")
    target = manifest.get("targetManifestDigest")
    reason = manifest.get("reason")
    if manifest_type == "release":
        if target is not None or reason is not None:
            raise ReleaseIntegrityError("Normal releases cannot carry restoration fields.")
    elif manifest_type == "restoration":
        if not isinstance(target, str) or not _HEX_64.fullmatch(target):
            raise ReleaseIntegrityError("Restoration requires an exact targetManifestDigest.")
        if not isinstance(reason, str) or not reason or reason != reason.strip():
            raise ReleaseIntegrityError("Restoration requires a canonical non-empty reason.")
    else:
        raise ReleaseIntegrityError("manifestType must be exactly release or restoration.")
    authority = manifest.get("authority")
    authority_keys = set(authority) if isinstance(authority, dict) else set()
    allowed_authority_keys = (
        (_AUTHORITY_KEYS,)
        if require_signature
        else (_AUTHORITY_KEYS, _AUTHORITY_METADATA_KEYS)
    )
    if not isinstance(authority, dict) or authority_keys not in allowed_authority_keys:
        raise ReleaseIntegrityError("Release authority attestation has an invalid exact contract.")
    if (
        type(authority.get("schemaVersion")) is not int
        or authority.get("schemaVersion") != 1
        or authority.get("algorithm") != "ed25519"
    ):
        raise ReleaseIntegrityError("Release authority algorithm contract must be Ed25519 v1.")
    if not isinstance(authority.get("keyId"), str) or not _HEX_64.fullmatch(authority["keyId"]):
        raise ReleaseIntegrityError("Release authority keyId must be exact lowercase SHA-256.")
    if "signature" in authority:
        signature_text = authority.get("signature")
        if not isinstance(signature_text, str) or not signature_text:
            raise ReleaseIntegrityError("Release manifest signature is required.")
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ReleaseIntegrityError("Release manifest signature is not canonical base64.") from error
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
            raise ReleaseIntegrityError("Release manifest signature must be one canonical Ed25519 signature.")
    return copy.deepcopy(manifest)


def _release_signing_payload(
    manifest: dict[str, Any], *, enforce_activation: bool
) -> bytes:
    document = _validate_manifest_contract(
        manifest,
        require_signature=False,
        enforce_activation=enforce_activation,
    )
    document["authority"].pop("signature", None)
    return canonical_json_bytes({"domain": RELEASE_SIGNING_DOMAIN, "manifest": document})


def release_signing_payload(manifest: dict[str, Any]) -> bytes:
    """Return current-activation bytes an external release authority must sign."""
    return _release_signing_payload(manifest, enforce_activation=True)


def _verify_release_manifest_at_home(
    home: Path,
    manifest: dict[str, Any],
    *,
    enforce_activation: bool = True,
) -> dict[str, Any]:
    """Verify exact manifest shape, policy, pinned key, clock, and signature."""

    normalized_home = _normalized_home(home)
    document = _validate_manifest_contract(
        manifest,
        enforce_activation=enforce_activation,
    )
    if verify_policy_anchor(normalized_home) != document["policyDigest"]:
        raise ReleaseIntegrityError("Release manifest is not bound to the installed immutable policy.")
    public_key, key_id = _verify_pinned_release_authority_at_home(normalized_home)
    if document["authority"]["keyId"] != key_id:
        raise ReleaseIntegrityError("Release manifest was signed by a non-canonical authority.")
    now = _utc_now()
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
    if _parse_timestamp(document["issuedAt"], "issuedAt") > now.astimezone(timezone.utc):
        raise ReleaseIntegrityError("Release manifest issuedAt cannot be in the future.")
    signature = base64.b64decode(document["authority"]["signature"], validate=True)
    try:
        public_key.verify(
            signature,
            _release_signing_payload(document, enforce_activation=enforce_activation),
        )
    except Exception as error:
        exceptions = importlib.import_module("cryptography.exceptions")
        if isinstance(error, exceptions.InvalidSignature):
            raise ReleaseIntegrityError("Release manifest signature is invalid.") from error
        raise ReleaseIntegrityError(f"Release manifest verification failed: {error}") from error
    return document


def _write_once_json(home: Path, path: Path, value: dict[str, Any]) -> None:
    path = assert_guardian_storage_path(home, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(home, path)
    payload = canonical_json_bytes(value)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        try:
            existing = read_canonical_json(path)
        except (OSError, ValueError, UnicodeError) as error:
            raise ReleaseIntegrityError(f"Append-only release evidence is invalid: {error}") from error
        if existing != value:
            raise ReleaseIntegrityError("Append-only release evidence cannot be rewritten.")
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if path.read_bytes() != payload:
        raise ReleaseIntegrityError("Append-only release evidence changed after creation.")


def _archive_artifact(home: Path, expected_digest: str, payload: bytes) -> Path:
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise ReleaseIntegrityError("Release artifact bytes do not match the signed artifactDigest.")
    path = _artifact_path(home, expected_digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert_guardian_storage_path(home, path)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise ReleaseIntegrityError(f"Archived release artifact is unreadable: {error}") from error
        if hashlib.sha256(existing).hexdigest() != expected_digest or existing != payload:
            raise ReleaseIntegrityError("Archived release artifact cannot be replaced.")
        return path
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
        raise ReleaseIntegrityError("Archived release artifact failed digest verification.")
    return path


@contextmanager
def _release_lock(home: Path, timeout_seconds: float = 5.0) -> Iterator[None]:
    root = _release_root(home)
    root.mkdir(parents=True, exist_ok=True)
    lock = assert_guardian_storage_path(home, root / "transaction.lock")
    token = f"guardian-release-lock-v1:{os.getpid()}:{uuid.uuid4().hex}\n".encode("ascii")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            descriptor = os.open(
                lock,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
            break
        except FileExistsError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReleaseIntegrityError(
                    "Release transaction lock is held; Guardian will not bypass it."
                ) from error
            time.sleep(min(0.01, remaining))
    try:
        if lock.read_bytes() != token:
            raise ReleaseIntegrityError("Release transaction lock changed after acquisition.")
        yield
    finally:
        if not lock.is_file() or lock.read_bytes() != token:
            raise ReleaseIntegrityError("Release transaction lock changed before release.")
        lock.unlink()


def _state_path(home: Path, channel: str) -> Path:
    if channel not in _CHANNELS:
        raise ReleaseIntegrityError("Release channel must be exactly canary or stable.")
    return assert_guardian_storage_path(
        home, _release_root(home) / "channels" / f"{channel}.json"
    )


def _history_root(home: Path, channel: str) -> Path:
    if channel not in _CHANNELS:
        raise ReleaseIntegrityError("Release channel must be exactly canary or stable.")
    return assert_guardian_storage_path(home, _release_root(home) / "history" / channel)


def _read_archived_manifest(home: Path, digest: str) -> dict[str, Any]:
    path = _manifest_path(home, digest)
    try:
        document = read_canonical_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise ReleaseIntegrityError(f"Archived release manifest is invalid: {error}") from error
    if sha256_digest(document) != digest:
        raise ReleaseIntegrityError("Archived release manifest digest is inconsistent.")
    return _verify_release_manifest_at_home(
        home,
        document,
        enforce_activation=False,
    )


def _archived_actions(
    home: Path, channel: str
) -> tuple[tuple[int, str, dict[str, Any]], ...]:
    root = assert_guardian_storage_path(home, _release_root(home) / "manifests")
    if not root.exists():
        return ()
    actions: list[tuple[int, str, dict[str, Any]]] = []
    seen_sequences: set[int] = set()
    for path in sorted(root.glob("*.json"), key=lambda item: item.name):
        digest = path.stem
        if not _HEX_64.fullmatch(digest):
            raise ReleaseIntegrityError("Archived release manifest filename is not canonical.")
        document = _read_archived_manifest(home, digest)
        if document["channel"] != channel:
            continue
        sequence = _positive_sequence(document["channelSequence"])
        if sequence in seen_sequences:
            raise ReleaseIntegrityError(
                "Multiple signed release actions claim the same channel sequence."
            )
        seen_sequences.add(sequence)
        actions.append((sequence, digest, document))
    actions.sort(key=lambda item: item[0])
    if tuple(item[0] for item in actions) != tuple(range(1, len(actions) + 1)):
        raise ReleaseIntegrityError(
            "Archived signed release action sequences are not contiguous."
        )
    return tuple(actions)


def _read_state(home: Path, channel: str) -> dict[str, Any] | None:
    path = _state_path(home, channel)
    if not path.exists():
        return None
    try:
        state = read_canonical_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise ReleaseIntegrityError(f"Release channel state is invalid: {error}") from error
    if not isinstance(state, dict) or set(state) != _STATE_KEYS:
        raise ReleaseIntegrityError("Release channel state has an invalid exact contract.")
    unsigned = {key: value for key, value in state.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(
            home,
            f"release-channel-state:v1:{channel}",
            unsigned,
            state["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise ReleaseIntegrityError(f"Release channel state seal is invalid: {error}") from error
    if (
        type(state.get("schemaVersion")) is not int
        or state.get("schemaVersion") != 1
        or state.get("channel") != channel
        or state.get("policyDigest") != verify_policy_anchor(home)
    ):
        raise ReleaseIntegrityError("Release channel state is not bound to this policy and channel.")
    _positive_sequence(state.get("channelSequence"))
    for field in ("actionManifestDigest", "activeManifestDigest", "artifactDigest"):
        if not isinstance(state.get(field), str) or not _HEX_64.fullmatch(state[field]):
            raise ReleaseIntegrityError("Release channel state contains an invalid digest.")
    if not isinstance(state.get("sourceCommit"), str) or not _FULL_COMMIT.fullmatch(
        state["sourceCommit"]
    ):
        raise ReleaseIntegrityError("Release channel state contains an invalid source commit.")
    _parse_semver(state.get("pluginVersion"), "channel.pluginVersion")
    event_recorded_at = _parse_timestamp(state.get("eventRecordedAt"), "channel.eventRecordedAt")
    activated_at = _parse_timestamp(state.get("activatedAt"), "channel.activatedAt")
    if activated_at < event_recorded_at:
        raise ReleaseIntegrityError(
            "Release channel activation time cannot precede its recorded history event."
        )
    observed_now = _utc_now()
    if not isinstance(observed_now, datetime) or observed_now.tzinfo is None:
        raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
    if event_recorded_at > observed_now.astimezone(timezone.utc) or activated_at > observed_now.astimezone(
        timezone.utc
    ):
        raise ReleaseIntegrityError(
            "Release channel timestamps cannot be later than the trusted host clock."
        )
    action = _read_archived_manifest(home, state["actionManifestDigest"])
    active = _read_archived_manifest(home, state["activeManifestDigest"])
    if event_recorded_at < _parse_timestamp(action["issuedAt"], "action.issuedAt"):
        raise ReleaseIntegrityError(
            "Release channel event time cannot precede its signed action issuance."
        )
    if (
        action.get("channel") != channel
        or action.get("channelSequence") != state["channelSequence"]
        or active.get("manifestType") != "release"
        or active.get("channel") != channel
    ):
        raise ReleaseIntegrityError("Active channel target must be an archived normal release.")
    if action.get("manifestType") == "release":
        if state["actionManifestDigest"] != state["activeManifestDigest"]:
            raise ReleaseIntegrityError("Normal release state must activate its signed action manifest.")
    elif action.get("manifestType") == "restoration":
        if action.get("targetManifestDigest") != state["activeManifestDigest"]:
            raise ReleaseIntegrityError("Restoration state differs from its signed target manifest.")
        if _coordinates(action) != _coordinates(active):
            raise ReleaseIntegrityError("Restoration state coordinates differ from its target.")
    else:
        raise ReleaseIntegrityError("Release channel state references an invalid action type.")
    coordinates = (active["pluginVersion"], active["sourceCommit"], active["artifactDigest"])
    if coordinates != (
        state["pluginVersion"],
        state["sourceCommit"],
        state["artifactDigest"],
    ):
        raise ReleaseIntegrityError("Release channel state differs from its active manifest.")
    _validate_canary_evidence(
        home,
        channel=channel,
        active_manifest=active,
        claimed_digest=state.get("canaryEvidenceDigest"),
    )
    artifact = _artifact_path(home, state["artifactDigest"])
    try:
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != state["artifactDigest"]:
            raise ReleaseIntegrityError("Active release artifact digest is invalid.")
    except OSError as error:
        raise ReleaseIntegrityError(f"Active release artifact is unavailable: {error}") from error
    return copy.deepcopy(state)


def _read_channel_state_at_home(home: Path, channel: str) -> dict[str, Any] | None:
    normalized_home = _normalized_home(home)
    _verify_pinned_release_authority_at_home(normalized_home)
    state = _read_state(normalized_home, channel)
    _validate_state_history_alignment(normalized_home, channel, state)
    return state


def _history_event_id(unsigned_without_event_id: dict[str, Any]) -> str:
    return sha256_digest(unsigned_without_event_id)


def _verify_history_entry(home: Path, channel: str, path: Path) -> dict[str, Any]:
    try:
        entry = read_canonical_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise ReleaseIntegrityError(f"Release history is invalid: {error}") from error
    if not isinstance(entry, dict) or set(entry) != _HISTORY_KEYS:
        raise ReleaseIntegrityError("Release history has an invalid exact contract.")
    unsigned = {key: value for key, value in entry.items() if key != "authoritySeal"}
    event_payload = {key: value for key, value in unsigned.items() if key != "eventId"}
    expected_id = _history_event_id(event_payload)
    sequence = _positive_sequence(entry.get("channelSequence"))
    expected_name = f"{sequence:020d}-{expected_id}.json"
    if entry.get("eventId") != expected_id or path.name != expected_name:
        raise ReleaseIntegrityError("Release history identity or filename is inconsistent.")
    try:
        verify_authority_seal(
            home,
            f"release-history:v1:{channel}",
            unsigned,
            entry["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise ReleaseIntegrityError(f"Release history seal is invalid: {error}") from error
    if (
        type(entry.get("schemaVersion")) is not int
        or entry.get("schemaVersion") != 1
        or entry.get("channel") != channel
        or entry.get("recordType") not in {"promotion", "restoration"}
        or entry.get("policyDigest") != verify_policy_anchor(home)
    ):
        raise ReleaseIntegrityError("Release history is not bound to this policy and channel.")
    for field in ("actionManifestDigest", "activeManifestDigest", "artifactDigest"):
        if not isinstance(entry.get(field), str) or not _HEX_64.fullmatch(entry[field]):
            raise ReleaseIntegrityError("Release history contains an invalid digest.")
    previous = entry.get("previousActiveManifestDigest")
    if previous is not None and (not isinstance(previous, str) or not _HEX_64.fullmatch(previous)):
        raise ReleaseIntegrityError("Release history contains an invalid previous manifest digest.")
    if not isinstance(entry.get("authorityKeyId"), str) or not _HEX_64.fullmatch(
        entry["authorityKeyId"]
    ):
        raise ReleaseIntegrityError("Release history contains an invalid authority keyId.")
    _, pinned_key_id = _verify_pinned_release_authority_at_home(home)
    if entry["authorityKeyId"] != pinned_key_id:
        raise ReleaseIntegrityError("Release history names a non-canonical authority keyId.")
    recorded_at = _parse_timestamp(entry.get("recordedAt"), "history.recordedAt")
    observed_now = _utc_now()
    if not isinstance(observed_now, datetime) or observed_now.tzinfo is None:
        raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
    if recorded_at > observed_now.astimezone(timezone.utc):
        raise ReleaseIntegrityError(
            "Release history recordedAt cannot be later than the trusted host clock."
        )
    action = _read_archived_manifest(home, entry["actionManifestDigest"])
    active = _read_archived_manifest(home, entry["activeManifestDigest"])
    if recorded_at < _parse_timestamp(action["issuedAt"], "action.issuedAt"):
        raise ReleaseIntegrityError(
            "Release history cannot predate its signed action issuance."
        )
    if action["channelSequence"] != sequence or action["channel"] != channel:
        raise ReleaseIntegrityError("Release history differs from its signed action manifest.")
    if active.get("manifestType") != "release" or active.get("channel") != channel:
        raise ReleaseIntegrityError("Release history active target must be a normal release.")
    if entry["recordType"] == "promotion":
        if (
            action.get("manifestType") != "release"
            or entry["actionManifestDigest"] != entry["activeManifestDigest"]
        ):
            raise ReleaseIntegrityError("Promotion history differs from its normal release action.")
    elif (
        action.get("manifestType") != "restoration"
        or action.get("targetManifestDigest") != entry["activeManifestDigest"]
        or _coordinates(action) != _coordinates(active)
    ):
        raise ReleaseIntegrityError("Restoration history differs from its signed target action.")
    if (entry["pluginVersion"], entry["sourceCommit"], entry["artifactDigest"]) != (
        active["pluginVersion"],
        active["sourceCommit"],
        active["artifactDigest"],
    ):
        raise ReleaseIntegrityError("Release history coordinates differ from its active release.")
    _validate_canary_evidence(
        home,
        channel=channel,
        active_manifest=active,
        claimed_digest=entry.get("canaryEvidenceDigest"),
    )
    return copy.deepcopy(entry)


def _read_release_history_entries_at_home(home: Path, channel: str) -> tuple[dict[str, Any], ...]:
    normalized_home = _normalized_home(home)
    _verify_pinned_release_authority_at_home(normalized_home)
    root = _history_root(normalized_home, channel)
    if not root.exists():
        return ()
    entries = tuple(
        _verify_history_entry(normalized_home, channel, path)
        for path in sorted(root.glob("*.json"), key=lambda item: item.name)
    )
    if tuple(entry["channelSequence"] for entry in entries) != tuple(range(1, len(entries) + 1)):
        raise ReleaseIntegrityError("Release history channel sequences are not contiguous.")
    previous_active: str | None = None
    previous_recorded_at: datetime | None = None
    for entry in entries:
        if entry["previousActiveManifestDigest"] != previous_active:
            raise ReleaseIntegrityError("Release history previous-active chain is inconsistent.")
        recorded_at = _parse_timestamp(entry["recordedAt"], "history.recordedAt")
        if previous_recorded_at is not None and recorded_at < previous_recorded_at:
            raise ReleaseIntegrityError("Release history recordedAt must be monotonic per channel.")
        previous_active = entry["activeManifestDigest"]
        previous_recorded_at = recorded_at
    return entries


def _state_matches_history(state: dict[str, Any], entry: dict[str, Any]) -> bool:
    return (
        state["channel"] == entry["channel"]
        and state["channelSequence"] == entry["channelSequence"]
        and state["actionManifestDigest"] == entry["actionManifestDigest"]
        and state["activeManifestDigest"] == entry["activeManifestDigest"]
        and state["pluginVersion"] == entry["pluginVersion"]
        and state["sourceCommit"] == entry["sourceCommit"]
        and state["artifactDigest"] == entry["artifactDigest"]
        and state["policyDigest"] == entry["policyDigest"]
        and state["canaryEvidenceDigest"] == entry["canaryEvidenceDigest"]
        and state["eventRecordedAt"] == entry["recordedAt"]
    )


def _validate_state_history_alignment(
    home: Path,
    channel: str,
    state: dict[str, Any] | None,
    *,
    pending_action_digest: str | None = None,
) -> tuple[dict[str, Any], ...]:
    history = _read_release_history_entries_at_home(home, channel)
    actions = _archived_actions(home, channel)
    history_actions = tuple(
        (entry["channelSequence"], entry["actionManifestDigest"])
        for entry in history
    )
    archived_actions = tuple((sequence, digest) for sequence, digest, _ in actions)
    if history_actions != archived_actions[: len(history_actions)]:
        raise ReleaseIntegrityError(
            "Release history is not an exact prefix of archived signed actions."
        )
    extra_actions = archived_actions[len(history_actions) :]
    if extra_actions and not (
        pending_action_digest is not None
        and len(extra_actions) == 1
        and extra_actions[0][0] == len(history_actions) + 1
        and extra_actions[0][1] == pending_action_digest
    ):
        raise ReleaseIntegrityError(
            "Release history was truncated below the archived signed-action high-water mark."
        )
    if state is None:
        if not history:
            return history
        pending = history[-1]
        if (
            pending_action_digest is not None
            and len(history) == 1
            and pending["channelSequence"] == 1
            and pending["actionManifestDigest"] == pending_action_digest
            and pending["previousActiveManifestDigest"] is None
        ):
            return history
        raise ReleaseIntegrityError("Release history exists without its channel state.")
    if history and _state_matches_history(state, history[-1]):
        return history
    if history and pending_action_digest is not None:
        pending = history[-1]
        if (
            pending["channelSequence"] == state["channelSequence"] + 1
            and pending["actionManifestDigest"] == pending_action_digest
            and pending["previousActiveManifestDigest"] == state["activeManifestDigest"]
            and len(history) == pending["channelSequence"]
        ):
            return history
    raise ReleaseIntegrityError("Release channel state is replayed or differs from append-only history.")



def _read_release_history_at_home(
    home: Path, channel: str
) -> tuple[dict[str, Any], ...]:
    normalized_home = _normalized_home(home)
    _verify_pinned_release_authority_at_home(normalized_home)
    state = _read_state(normalized_home, channel)
    return _validate_state_history_alignment(normalized_home, channel, state)

def _coordinates(manifest: dict[str, Any]) -> tuple[Any, ...]:
    return (
        manifest["pluginVersion"],
        manifest["sourceCommit"],
        manifest["artifactDigest"],
        manifest["policyDigest"],
        manifest["stateSchemaVersion"],
        canonical_json_bytes(manifest["runtimeCompatibility"]),
    )


def _stable_matching_canary_event(
    home: Path, manifest: dict[str, Any]
) -> dict[str, Any] | None:
    for entry in _read_release_history_at_home(home, "canary"):
        if entry["recordType"] != "promotion":
            continue
        candidate = _read_archived_manifest(home, entry["activeManifestDigest"])
        if _coordinates(candidate) == _coordinates(manifest):
            return entry
    return None


def _validate_canary_evidence(
    home: Path,
    *,
    channel: str,
    active_manifest: dict[str, Any],
    claimed_digest: Any,
) -> None:
    if channel == "canary":
        if claimed_digest is not None:
            raise ReleaseIntegrityError("Canary records cannot claim stable-channel evidence.")
        return
    if not isinstance(claimed_digest, str) or not _HEX_64.fullmatch(claimed_digest):
        raise ReleaseIntegrityError(
            "Stable state and history require an exact sealed canary evidence digest."
        )
    for entry in _read_release_history_at_home(home, "canary"):
        if sha256_digest(entry) != claimed_digest or entry["recordType"] != "promotion":
            continue
        candidate = _read_archived_manifest(home, entry["activeManifestDigest"])
        if _coordinates(candidate) == _coordinates(active_manifest):
            return
    raise ReleaseIntegrityError(
        "Stable canary evidence is unavailable, changed, or no longer proves this release."
    )


def _archive_manifest(home: Path, manifest: dict[str, Any]) -> tuple[str, Path]:
    digest = sha256_digest(manifest)
    path = _manifest_path(home, digest)
    _write_once_json(home, path, manifest)
    return digest, path


def _existing_result(
    home: Path, channel: str, state: dict[str, Any], action_digest: str
) -> ReleaseResult | None:
    if state.get("actionManifestDigest") != action_digest:
        return None
    history = _read_release_history_at_home(home, channel)
    if not history:
        raise ReleaseIntegrityError("Current release state has no append-only history.")
    entry = history[-1]
    if entry["actionManifestDigest"] != action_digest:
        raise ReleaseIntegrityError("Current release state differs from the latest history event.")
    root = _history_root(home, channel)
    path = root / f"{entry['channelSequence']:020d}-{entry['eventId']}.json"
    return ReleaseResult(
        channel=channel,
        record_type=entry["recordType"],
        action_manifest_digest=action_digest,
        active_manifest_digest=entry["activeManifestDigest"],
        history_path=path,
        state_path=_state_path(home, channel),
    )


def _apply_release_action(
    home: Path,
    manifest: dict[str, Any],
    *,
    expected_type: str,
    artifact_path: Path | None,
) -> ReleaseResult:
    normalized_home = _normalized_home(home)
    action = _verify_release_manifest_at_home(normalized_home, manifest)
    if action["manifestType"] != expected_type:
        raise ReleaseIntegrityError(f"Expected a signed {expected_type} manifest.")
    artifact_payload: bytes | None = None
    if expected_type == "release":
        if artifact_path is None or is_link_or_reparse(artifact_path):
            raise ReleaseIntegrityError("Promotion requires a regular, non-redirected release artifact.")
        try:
            if not stat.S_ISREG(artifact_path.lstat().st_mode):
                raise ReleaseIntegrityError("Promotion artifact must be a regular file.")
            artifact_payload = artifact_path.read_bytes()
        except OSError as error:
            raise ReleaseIntegrityError(f"Promotion artifact cannot be read: {error}") from error
        if hashlib.sha256(artifact_payload).hexdigest() != action["artifactDigest"]:
            raise ReleaseIntegrityError("Promotion artifact differs from the signed artifactDigest.")
    elif artifact_path is not None:
        raise ReleaseIntegrityError("Restoration uses an archived artifact and accepts no replacement bytes.")

    action_digest = sha256_digest(action)
    channel = action["channel"]
    with _release_lock(normalized_home):
        current = _read_state(normalized_home, channel)
        aligned_history = _validate_state_history_alignment(
            normalized_home,
            channel,
            current,
            pending_action_digest=action_digest,
        )
        if current is not None:
            existing = _existing_result(normalized_home, channel, current, action_digest)
            if existing is not None:
                return existing
        expected_sequence = 1 if current is None else current["channelSequence"] + 1
        if action["channelSequence"] != expected_sequence:
            raise ReleaseIntegrityError(
                "Signed channelSequence must advance exactly one from append-only history."
            )

        if expected_type == "release":
            for previous in aligned_history:
                if previous["recordType"] != "promotion":
                    continue
                if previous["actionManifestDigest"] == action_digest:
                    continue
                previous_manifest = _read_archived_manifest(
                    normalized_home, previous["activeManifestDigest"]
                )
                if _compare_semver(action["pluginVersion"], previous_manifest["pluginVersion"]) <= 0:
                    raise ReleaseIntegrityError(
                        "Normal release promotion must exceed every SemVer previously promoted on the channel."
                    )
            canary_evidence_digest: str | None = None
            if channel == "stable":
                canary_event = _stable_matching_canary_event(normalized_home, action)
                if canary_event is None:
                    raise ReleaseIntegrityError(
                        "Stable promotion requires the exact signed artifact, commit, and version in canary history."
                    )
                canary_evidence_digest = sha256_digest(canary_event)
            active = action
            active_digest = action_digest
        else:
            canary_evidence_digest = None
            if current is None:
                raise ReleaseIntegrityError("Restoration requires an existing active channel release.")
            target_digest = action["targetManifestDigest"]
            target = _read_archived_manifest(normalized_home, target_digest)
            if target["manifestType"] != "release" or target["channel"] != channel:
                raise ReleaseIntegrityError(
                    "Restoration target must be a normal release previously promoted on this channel."
                )
            if not any(
                entry["recordType"] == "promotion"
                and entry["activeManifestDigest"] == target_digest
                for entry in aligned_history
            ):
                raise ReleaseIntegrityError("Restoration target was never promoted on this channel.")
            if target_digest == current["activeManifestDigest"]:
                raise ReleaseIntegrityError("Restoration target is already active.")
            if _coordinates(target) != _coordinates(action):
                raise ReleaseIntegrityError(
                    "Restoration coordinates must exactly match the archived target release."
                )
            if channel == "stable":
                target_promotion = next(
                    (
                        entry
                        for entry in aligned_history
                        if entry["recordType"] == "promotion"
                        and entry["activeManifestDigest"] == target_digest
                    ),
                    None,
                )
                if target_promotion is None:
                    raise ReleaseIntegrityError(
                        "Stable restoration target has no preserved canary promotion proof."
                    )
                canary_evidence_digest = target_promotion["canaryEvidenceDigest"]
                _validate_canary_evidence(
                    normalized_home,
                    channel=channel,
                    active_manifest=target,
                    claimed_digest=canary_evidence_digest,
                )
            archived_artifact = _artifact_path(normalized_home, target["artifactDigest"])
            try:
                if hashlib.sha256(archived_artifact.read_bytes()).hexdigest() != target[
                    "artifactDigest"
                ]:
                    raise ReleaseIntegrityError("Restoration target artifact digest is invalid.")
            except OSError as error:
                raise ReleaseIntegrityError(f"Restoration target artifact is unavailable: {error}") from error
            active = target
            active_digest = target_digest

        _archive_manifest(normalized_home, action)
        if artifact_payload is not None:
            _archive_artifact(normalized_home, action["artifactDigest"], artifact_payload)

        _, key_id = _verify_pinned_release_authority_at_home(normalized_home)
        pending_event = (
            aligned_history[-1]
            if aligned_history and aligned_history[-1]["actionManifestDigest"] == action_digest
            else None
        )
        if pending_event is not None:
            recorded_at = pending_event["recordedAt"]
        else:
            recorded_now = _utc_now()
            if not isinstance(recorded_now, datetime) or recorded_now.tzinfo is None:
                raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
            recorded_value = recorded_now.astimezone(timezone.utc)
            if recorded_value < _parse_timestamp(action["issuedAt"], "action.issuedAt"):
                raise ReleaseIntegrityError(
                    "Release event time cannot precede its signed action issuance."
                )
            if aligned_history and recorded_value < _parse_timestamp(
                aligned_history[-1]["recordedAt"], "history.recordedAt"
            ):
                raise ReleaseIntegrityError(
                    "Release event time cannot move backward from prior channel history."
                )
            if current is not None and recorded_value < _parse_timestamp(
                current["activatedAt"], "channel.activatedAt"
            ):
                raise ReleaseIntegrityError(
                    "Release event time cannot precede the prior channel activation."
                )
            recorded_at = _timestamp(recorded_value)
        event_payload = {
            "schemaVersion": 1,
            "recordType": "promotion" if expected_type == "release" else "restoration",
            "channel": channel,
            "channelSequence": action["channelSequence"],
            "actionManifestDigest": action_digest,
            "activeManifestDigest": active_digest,
            "previousActiveManifestDigest": (
                None if current is None else current["activeManifestDigest"]
            ),
            "pluginVersion": active["pluginVersion"],
            "sourceCommit": active["sourceCommit"],
            "artifactDigest": active["artifactDigest"],
            "policyDigest": action["policyDigest"],
            "canaryEvidenceDigest": canary_evidence_digest,
            "authorityKeyId": key_id,
            "recordedAt": recorded_at,
        }
        event_id = _history_event_id(event_payload)
        unsigned_event = {**event_payload, "eventId": event_id}
        event = {
            **unsigned_event,
            "authoritySeal": authority_seal(
                normalized_home,
                f"release-history:v1:{channel}",
                unsigned_event,
            ),
        }
        history_path = (
            _history_root(normalized_home, channel)
            / f"{action['channelSequence']:020d}-{event_id}.json"
        )
        _write_once_json(normalized_home, history_path, event)

        activated_now = _utc_now()
        if not isinstance(activated_now, datetime) or activated_now.tzinfo is None:
            raise ReleaseIntegrityError("Trusted release clock must be timezone-aware.")
        activated_value = activated_now.astimezone(timezone.utc)
        if activated_value < _parse_timestamp(recorded_at, "history.recordedAt"):
            raise ReleaseIntegrityError(
                "Release activation time cannot precede its recorded history event."
            )
        if current is not None and activated_value < _parse_timestamp(
            current["activatedAt"], "channel.activatedAt"
        ):
            raise ReleaseIntegrityError(
                "Release activation time cannot move backward from the prior activation."
            )
        activated_at = _timestamp(activated_value)
        unsigned_state = {
            "schemaVersion": 1,
            "channel": channel,
            "channelSequence": action["channelSequence"],
            "actionManifestDigest": action_digest,
            "activeManifestDigest": active_digest,
            "pluginVersion": active["pluginVersion"],
            "sourceCommit": active["sourceCommit"],
            "artifactDigest": active["artifactDigest"],
            "policyDigest": action["policyDigest"],
            "canaryEvidenceDigest": canary_evidence_digest,
            "eventRecordedAt": recorded_at,
            "activatedAt": activated_at,
        }
        state = {
            **unsigned_state,
            "authoritySeal": authority_seal(
                normalized_home,
                f"release-channel-state:v1:{channel}",
                unsigned_state,
            ),
        }
        state_path = _state_path(normalized_home, channel)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        contained_atomic_write_json(normalized_home, state_path, state)
        if _read_state(normalized_home, channel) != state:
            raise ReleaseIntegrityError("Release channel state failed post-write verification.")
        _validate_state_history_alignment(normalized_home, channel, state)
        history = _read_release_history_at_home(normalized_home, channel)
        if not history or history[-1] != event:
            raise ReleaseIntegrityError("Append-only release history failed post-write verification.")
        if verify_policy_anchor(normalized_home) != EXPECTED_POLICY_SHA256:
            raise ReleaseIntegrityError("Immutable policy changed during release action.")
        return ReleaseResult(
            channel=channel,
            record_type=event["recordType"],
            action_manifest_digest=action_digest,
            active_manifest_digest=active_digest,
            history_path=history_path,
            state_path=state_path,
        )


def _promote_release_at_home(home: Path, manifest: dict[str, Any], artifact_path: Path) -> ReleaseResult:
    """Promote one externally signed normal release into canary or stable."""

    return _apply_release_action(
        home,
        manifest,
        expected_type="release",
        artifact_path=artifact_path,
    )


def _rollback_release_at_home(home: Path, restoration_manifest: dict[str, Any]) -> ReleaseResult:
    """Apply a new externally signed restoration without deleting history."""

    return _apply_release_action(
        home,
        restoration_manifest,
        expected_type="restoration",
        artifact_path=None,
    )


def enroll_release_authority(public_key_path: Path) -> str:
    """Pin the release authority only in the canonical host trust root."""
    return _enroll_release_authority_at_home(default_guardian_home(), public_key_path)


def verify_pinned_release_authority() -> tuple[Any, str]:
    """Verify the release authority only in the canonical host trust root."""
    return _verify_pinned_release_authority_at_home(default_guardian_home())


def verify_release_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return _verify_release_manifest_at_home(default_guardian_home(), manifest)


def _block_unimplemented_external_release_head_provider() -> None:
    from .release_head_provider import block_unimplemented_canonical_release_head_provider

    block_unimplemented_canonical_release_head_provider()


def read_channel_state(channel: str) -> dict[str, Any] | None:
    _block_unimplemented_external_release_head_provider()
    return _read_channel_state_at_home(default_guardian_home(), channel)


def read_release_history(channel: str) -> tuple[dict[str, Any], ...]:
    _block_unimplemented_external_release_head_provider()
    return _read_release_history_at_home(default_guardian_home(), channel)


def promote_release(manifest: dict[str, Any], artifact_path: Path) -> ReleaseResult:
    _block_unimplemented_external_release_head_provider()
    return _promote_release_at_home(default_guardian_home(), manifest, artifact_path)


def rollback_release(restoration_manifest: dict[str, Any]) -> ReleaseResult:
    _block_unimplemented_external_release_head_provider()
    return _rollback_release_at_home(default_guardian_home(), restoration_manifest)

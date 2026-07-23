"""Detached Ed25519 catalog-approval verification; verification only."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import importlib
import importlib.metadata
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .authority import AuthorityIntegrityError, verify_authority_seal
from .canonical import canonical_json_bytes, read_canonical_json, sha256_digest
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path, is_link_or_reparse


PINNED_CRYPTOGRAPHY_VERSION = "46.0.7"
CATALOG_APPROVAL_DOMAIN = "design-system-guardian.catalog-approval.v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ATTESTATION_KEYS = {"schemaVersion", "algorithm", "keyId", "sequence", "issuedAt", "signature"}
_MAX_APPROVAL_SEQUENCE = (1 << 63) - 1
_BINDING_KEYS = {"schemaVersion", "algorithm", "keyId", "publicKeyDigest", "authoritySeal"}
CATALOG_AUTHORITY_BINDING_PURPOSE = "catalog-authority-binding:v1"


class CatalogAuthorityError(ValueError):
    """Raised when catalog authority bootstrap or approval evidence is invalid."""


def _load_crypto_runtime() -> tuple[str, Any, type[Any], type[BaseException]]:
    try:
        version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError as error:
        raise CatalogAuthorityError(
            f"Required runtime dependency cryptography=={PINNED_CRYPTOGRAPHY_VERSION} is not installed."
        ) from error
    except (OSError, ValueError) as error:
        raise CatalogAuthorityError(
            "The installed cryptography runtime version cannot be determined."
        ) from error
    if version != PINNED_CRYPTOGRAPHY_VERSION:
        raise CatalogAuthorityError(
            f"Runtime dependency cryptography must be exactly {PINNED_CRYPTOGRAPHY_VERSION}; found {version}."
        )
    try:
        serialization = importlib.import_module("cryptography.hazmat.primitives.serialization")
        ed25519 = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")
        exceptions = importlib.import_module("cryptography.exceptions")
        public_key_type = ed25519.Ed25519PublicKey
        invalid_signature_type = exceptions.InvalidSignature
    except (AttributeError, ImportError, OSError) as error:
        raise CatalogAuthorityError(
            "The pinned cryptography verification runtime cannot be imported."
        ) from error
    if not isinstance(public_key_type, type):
        raise CatalogAuthorityError(
            "The pinned cryptography runtime does not expose Ed25519PublicKey."
        )
    if not isinstance(invalid_signature_type, type) or not issubclass(
        invalid_signature_type, BaseException
    ):
        raise CatalogAuthorityError(
            "The pinned cryptography runtime does not expose InvalidSignature."
        )
    return version, serialization, public_key_type, invalid_signature_type


def verify_runtime_dependency() -> str:
    version, _, _, _ = _load_crypto_runtime()
    return version


def _canonical_public_key(payload: bytes) -> tuple[Any, bytes, str]:
    _, serialization, public_key_type, _ = _load_crypto_runtime()
    try:
        public_key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as error:
        raise CatalogAuthorityError(f"Catalog authority public key is not valid PEM: {error}") from error
    if not isinstance(public_key, public_key_type):
        raise CatalogAuthorityError("Catalog authority public key must be Ed25519.")
    canonical_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key, canonical_pem, hashlib.sha256(public_der).hexdigest()


def read_catalog_authority_public_key(path: Path) -> tuple[bytes, str]:
    try:
        payload = path.expanduser().read_bytes()
    except OSError as error:
        raise CatalogAuthorityError(f"Catalog authority public key cannot be read: {error}") from error
    _, canonical_pem, key_id = _canonical_public_key(payload)
    return canonical_pem, key_id


def catalog_authority_binding_payload(canonical_pem: bytes, key_id: str) -> dict[str, Any]:
    if not isinstance(canonical_pem, bytes) or not canonical_pem:
        raise CatalogAuthorityError("Catalog authority binding requires canonical public PEM bytes.")
    if not isinstance(key_id, str) or not _HEX_64.fullmatch(key_id):
        raise CatalogAuthorityError("Catalog authority binding requires an exact Ed25519 keyId.")
    return {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "keyId": key_id,
        "publicKeyDigest": hashlib.sha256(canonical_pem).hexdigest(),
    }

def verify_pinned_catalog_authority(home: Path) -> tuple[Any, str]:
    normalized_home = home.expanduser().absolute()
    paths = GuardianPaths(normalized_home)
    key_path = paths.catalog_authority_public_key
    binding_path = paths.catalog_authority_binding
    try:
        assert_guardian_storage_path(normalized_home, key_path)
        assert_guardian_storage_path(normalized_home, binding_path)
    except PathIntegrityError as error:
        raise CatalogAuthorityError(str(error)) from error
    if is_link_or_reparse(key_path) or is_link_or_reparse(binding_path):
        raise CatalogAuthorityError("Pinned catalog authority evidence may not be redirected.")
    try:
        key_metadata = key_path.lstat()
        binding_metadata = binding_path.lstat()
        payload = key_path.read_bytes()
        binding = read_canonical_json(binding_path)
    except (OSError, ValueError, UnicodeError) as error:
        raise CatalogAuthorityError(
            f"Pinned catalog authority evidence is missing, unreadable, or non-canonical: {error}"
        ) from error
    if not stat.S_ISREG(key_metadata.st_mode) or not stat.S_ISREG(binding_metadata.st_mode):
        raise CatalogAuthorityError("Pinned catalog authority evidence must use regular files.")
    public_key, canonical_pem, key_id = _canonical_public_key(payload)
    if payload != canonical_pem:
        raise CatalogAuthorityError("Pinned catalog authority public key is not canonical PEM.")
    if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
        raise CatalogAuthorityError("Pinned catalog authority binding has an invalid exact contract.")
    unsigned = {key: value for key, value in binding.items() if key != "authoritySeal"}
    expected = catalog_authority_binding_payload(canonical_pem, key_id)
    if unsigned != expected:
        raise CatalogAuthorityError(
            "Pinned catalog authority public key differs from create-once trust evidence."
        )
    try:
        verify_authority_seal(
            normalized_home,
            CATALOG_AUTHORITY_BINDING_PURPOSE,
            unsigned,
            binding["authoritySeal"],
        )
    except AuthorityIntegrityError as error:
        raise CatalogAuthorityError(
            f"Pinned catalog authority binding seal is invalid: {error}"
        ) from error
    assert_guardian_storage_path(normalized_home, key_path)
    assert_guardian_storage_path(normalized_home, binding_path)
    return public_key, key_id


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CatalogAuthorityError(f"{field} must be an ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CatalogAuthorityError(f"{field} is not a valid ISO 8601 timestamp.") from error
    if parsed.tzinfo is None:
        raise CatalogAuthorityError(f"{field} must include an explicit UTC offset.")
    return parsed.astimezone(timezone.utc)


def _validate_approval_sequence(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_APPROVAL_SEQUENCE
    ):
        raise CatalogAuthorityError(
            "Catalog approval sequence must be an integer greater than or equal to 1 "
            f"and at most {_MAX_APPROVAL_SEQUENCE}."
        )
    return value


def catalog_approval_payload(
    *,
    policy_digest: str,
    profile_digest: str,
    catalog: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(policy_digest, str) or not _HEX_64.fullmatch(policy_digest):
        raise CatalogAuthorityError("Catalog approval requires the exact immutable policy digest.")
    if not isinstance(profile_digest, str) or not _HEX_64.fullmatch(profile_digest):
        raise CatalogAuthorityError("Catalog approval requires the exact installed profile digest.")
    if not isinstance(catalog, dict):
        raise CatalogAuthorityError("Catalog approval document must be an object.")
    attestation = catalog.get("approvalAttestation")
    if not isinstance(attestation, dict) or set(attestation) != _ATTESTATION_KEYS:
        raise CatalogAuthorityError("Catalog approvalAttestation has unknown or missing fields.")
    metadata = {key: copy.deepcopy(value) for key, value in attestation.items() if key != "signature"}
    _validate_approval_sequence(metadata.get("sequence"))
    unsigned_catalog = {key: copy.deepcopy(value) for key, value in catalog.items() if key != "approvalAttestation"}
    payload = canonical_json_bytes(
        {
            "domain": CATALOG_APPROVAL_DOMAIN,
            "policyDigest": policy_digest,
            "profileDigest": profile_digest,
            "attestation": metadata,
            "catalog": unsigned_catalog,
        }
    )
    return payload, metadata


def verify_catalog_approval(
    home: Path,
    *,
    policy_digest: str,
    profile: dict[str, Any],
    catalog: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    _, _, _, invalid_signature_type = _load_crypto_runtime()
    public_key, pinned_key_id = verify_pinned_catalog_authority(home)
    profile_digest = sha256_digest(profile)
    payload, metadata = catalog_approval_payload(
        policy_digest=policy_digest,
        profile_digest=profile_digest,
        catalog=catalog,
    )
    attestation = catalog["approvalAttestation"]
    if metadata.get("schemaVersion") != 1 or metadata.get("algorithm") != "ed25519":
        raise CatalogAuthorityError("Catalog approval algorithm contract must be exactly Ed25519 v1.")
    if metadata.get("keyId") != pinned_key_id:
        raise CatalogAuthorityError("Catalog approval keyId differs from the pinned authority.")
    assessment = now.astimezone(timezone.utc) if now.tzinfo is not None else None
    if assessment is None:
        raise CatalogAuthorityError("Catalog approval verification clock must be timezone-aware.")
    issued_at = _parse_timestamp(metadata.get("issuedAt"), "approvalAttestation.issuedAt")
    created_at = _parse_timestamp(catalog.get("createdAt"), "createdAt")
    if issued_at < created_at:
        raise CatalogAuthorityError("Catalog approval cannot predate the catalog it approves.")
    if issued_at > assessment:
        raise CatalogAuthorityError("Catalog approval issuedAt cannot be in the future.")
    signature_text = attestation.get("signature")
    if not isinstance(signature_text, str) or not signature_text:
        raise CatalogAuthorityError("Catalog approval signature must be canonical base64 text.")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CatalogAuthorityError("Catalog approval signature is not canonical base64.") from error
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
        raise CatalogAuthorityError("Catalog approval signature must be one canonical Ed25519 signature.")
    try:
        public_key.verify(signature, payload)
    except invalid_signature_type as error:
        raise CatalogAuthorityError("Catalog approval signature is invalid.") from error
    return copy.deepcopy(metadata)

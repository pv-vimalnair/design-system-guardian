"""Strict external Ed25519 and host-local personal catalog approval."""

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
from .authority import authority_seal, verify_authority_key_file
from .canonical import canonical_json_bytes, read_canonical_json, sha256_digest
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path, is_link_or_reparse
from .storage import profile_transaction_lock


PINNED_CRYPTOGRAPHY_VERSION = "46.0.7"
CATALOG_APPROVAL_DOMAIN = "design-system-guardian.catalog-approval.v1"
PERSONAL_CATALOG_APPROVAL_PURPOSE = "personal-catalog-approval:v1"
PERSONAL_CATALOG_ALGORITHM = "hmac-sha256"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_GENERATED_PERSONAL_PROFILE_ID = re.compile(r"^personal-[0-9a-f]{40}$")
_ATTESTATION_KEYS = {"schemaVersion", "algorithm", "keyId", "sequence", "issuedAt", "signature"}
_MAX_APPROVAL_SEQUENCE = (1 << 63) - 1
_BINDING_KEYS = {"schemaVersion", "algorithm", "keyId", "publicKeyDigest", "authoritySeal"}
CATALOG_AUTHORITY_BINDING_PURPOSE = "catalog-authority-binding:v1"


class CatalogAuthorityError(ValueError):
    """Raised when catalog authority bootstrap or approval evidence is invalid."""

def is_generated_personal_profile_id(value: Any) -> bool:
    """Return whether value is in Guardian's reserved generated-profile namespace."""

    return isinstance(value, str) and _GENERATED_PERSONAL_PROFILE_ID.fullmatch(value) is not None



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

def personal_catalog_authority_key_id(home: Path) -> str:
    """Return a non-secret identity for the host-owned personal HMAC authority."""

    normalized_home = home.expanduser().absolute()
    verify_authority_key_file(normalized_home)
    try:
        key = GuardianPaths(normalized_home).snapshot_authority_key.read_bytes()
    except OSError as error:
        raise CatalogAuthorityError(
            f"Personal catalog authority cannot be read: {error}"
        ) from error
    return hashlib.sha256(
        b"design-system-guardian.personal-catalog-authority.v1\0" + key
    ).hexdigest()


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

_external_catalog_approval_verifier = verify_catalog_approval


def _load_personal_profile_authority(
    home: Path,
    profile_id: str,
    *,
    missing_ok: bool,
) -> dict[str, Any] | None:
    try:
        from .personal_selection import load_personal_profile_authority

        binding = load_personal_profile_authority(
            home,
            profile_id,
            missing_ok=missing_ok,
        )
    except (ImportError, OSError, ValueError) as error:
        raise CatalogAuthorityError(
            f"Personal profile authority is invalid: {error}"
        ) from error
    if binding is None:
        if missing_ok:
            return None
        raise CatalogAuthorityError("Personal profile authority is missing.")
    if not isinstance(binding, dict):
        raise CatalogAuthorityError("Personal profile authority must be an object.")
    return binding


def _personal_catalog_seal_payload(
    payload: bytes,
    binding: dict[str, Any],
) -> dict[str, Any]:
    selection_set_digest = binding.get("selectionSetDigest")
    profile_id = binding.get("profileId")
    if not isinstance(selection_set_digest, str) or not _HEX_64.fullmatch(
        selection_set_digest
    ):
        raise CatalogAuthorityError(
            "Personal profile authority selectionSetDigest is invalid."
        )
    if not isinstance(profile_id, str) or not profile_id:
        raise CatalogAuthorityError("Personal profile authority profileId is invalid.")
    return {
        "schemaVersion": 1,
        "profileId": profile_id,
        "selectionSetDigest": selection_set_digest,
        "catalogApprovalPayloadDigest": sha256_digest(payload),
    }


def _verify_personal_catalog_approval(
    home: Path,
    *,
    policy_digest: str,
    profile: dict[str, Any],
    catalog: dict[str, Any],
    now: datetime,
    binding: dict[str, Any],
) -> dict[str, Any]:
    profile_digest = sha256_digest(profile)
    if (
        binding.get("authorityMode") != "personal_local"
        or binding.get("profileId") != profile.get("profileId")
        or binding.get("profileDigest") != profile_digest
    ):
        raise CatalogAuthorityError(
            "Personal profile authority does not match the exact installed profile."
        )
    payload, metadata = catalog_approval_payload(
        policy_digest=policy_digest,
        profile_digest=profile_digest,
        catalog=catalog,
    )
    if (
        metadata.get("schemaVersion") != 1
        or metadata.get("algorithm") != PERSONAL_CATALOG_ALGORITHM
    ):
        raise CatalogAuthorityError(
            "Personal catalog approval algorithm must be exactly HMAC-SHA256 v1."
        )
    expected_key_id = personal_catalog_authority_key_id(home)
    if metadata.get("keyId") != expected_key_id:
        raise CatalogAuthorityError(
            "Personal catalog approval keyId differs from the host authority."
        )
    assessment = now.astimezone(timezone.utc) if now.tzinfo is not None else None
    if assessment is None:
        raise CatalogAuthorityError(
            "Catalog approval verification clock must be timezone-aware."
        )
    issued_at = _parse_timestamp(
        metadata.get("issuedAt"),
        "approvalAttestation.issuedAt",
    )
    created_at = _parse_timestamp(catalog.get("createdAt"), "createdAt")
    if issued_at < created_at:
        raise CatalogAuthorityError(
            "Catalog approval cannot predate the catalog it approves."
        )
    if issued_at > assessment:
        raise CatalogAuthorityError(
            "Catalog approval issuedAt cannot be in the future."
        )
    signature = catalog["approvalAttestation"].get("signature")
    if not isinstance(signature, str) or not _HEX_64.fullmatch(signature):
        raise CatalogAuthorityError(
            "Personal catalog approval signature must be one lowercase SHA-256 HMAC."
        )
    try:
        verify_authority_seal(
            home.expanduser().absolute(),
            PERSONAL_CATALOG_APPROVAL_PURPOSE,
            _personal_catalog_seal_payload(payload, binding),
            signature,
        )
    except AuthorityIntegrityError as error:
        raise CatalogAuthorityError(
            f"Personal catalog approval signature is invalid: {error}"
        ) from error
    return copy.deepcopy(metadata)


def _load_current_personal_snapshot(
    home: Path,
    profile_id: str,
) -> dict[str, Any] | None:
    normalized_home = home.expanduser().absolute()
    try:
        with profile_transaction_lock(normalized_home, profile_id):
            paths = GuardianPaths(normalized_home)
            current_path = paths.profile(profile_id) / "current-snapshot.json"
            history_roots = (
                paths.snapshots(profile_id),
                paths.profile(profile_id) / "approval-sequences",
            )
            if not current_path.is_file():
                try:
                    retained = any(
                        root.is_dir() and any(root.iterdir())
                        for root in history_roots
                    )
                except OSError as error:
                    raise CatalogAuthorityError(
                        f"Personal catalog history cannot be inspected: {error}"
                    ) from error
                if not retained:
                    return None

            # A write-capable apply may resume after an interrupted promotion.
            # The profile lock prevents recovery from replacing a newer pointer.
            from .snapshot import load_snapshot

            return load_snapshot(normalized_home, profile_id)
    except CatalogAuthorityError:
        raise
    except (ImportError, OSError, TimeoutError, ValueError) as error:
        raise CatalogAuthorityError(
            f"Current personal catalog snapshot is invalid: {error}"
        ) from error


def create_personal_catalog_approval(
    home: Path,
    *,
    policy_digest: str,
    profile: dict[str, Any],
    catalog: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a host-HMAC-approved catalog for one sealed personal profile."""

    if not isinstance(profile, dict) or not isinstance(profile.get("profileId"), str):
        raise CatalogAuthorityError(
            "Personal catalog approval requires one exact profile."
        )
    if not isinstance(catalog, dict):
        raise CatalogAuthorityError(
            "Personal catalog approval requires one catalog object."
        )
    if "approvalAttestation" in catalog:
        raise CatalogAuthorityError(
            "Personal catalog approval accepts only an unsigned catalog."
        )
    normalized_home = home.expanduser().absolute()
    binding = _load_personal_profile_authority(
        normalized_home,
        profile["profileId"],
        missing_ok=False,
    )
    assert binding is not None
    profile_digest = sha256_digest(profile)
    if binding.get("profileDigest") != profile_digest:
        raise CatalogAuthorityError(
            "Personal profile authority does not match the catalog profile."
        )
    current = _load_current_personal_snapshot(
        normalized_home,
        profile["profileId"],
    )
    if current is not None:
        previous = copy.deepcopy(current.get("catalogEvidence"))
        if not isinstance(previous, dict):
            raise CatalogAuthorityError(
                "Current personal snapshot lacks catalog evidence."
            )
        previous_unsigned = {
            key: value
            for key, value in previous.items()
            if key != "approvalAttestation"
        }
        if previous_unsigned == catalog:
            prior_attestation = previous.get("approvalAttestation")
            if not isinstance(prior_attestation, dict):
                raise CatalogAuthorityError(
                    "Current personal catalog approval is missing."
                )
            prior_issued_at = _parse_timestamp(
                prior_attestation.get("issuedAt"),
                "approvalAttestation.issuedAt",
            )
            _verify_personal_catalog_approval(
                normalized_home,
                policy_digest=policy_digest,
                profile=profile,
                catalog=previous,
                now=prior_issued_at,
                binding=binding,
            )
            return previous
        sequence = current.get("approvalSequence")
        _validate_approval_sequence(sequence)
        if sequence == _MAX_APPROVAL_SEQUENCE:
            raise CatalogAuthorityError(
                "Personal catalog approval sequence is exhausted."
            )
        sequence += 1
    else:
        sequence = 1

    created_at = _parse_timestamp(catalog.get("createdAt"), "createdAt")
    issued_at = (
        created_at
        if now is None
        else now.astimezone(timezone.utc)
        if now.tzinfo is not None
        else None
    )
    if issued_at is None:
        raise CatalogAuthorityError(
            "Personal catalog approval clock must be timezone-aware."
        )
    issued_at_text = issued_at.isoformat().replace("+00:00", "Z")
    metadata = {
        "schemaVersion": 1,
        "algorithm": PERSONAL_CATALOG_ALGORITHM,
        "keyId": personal_catalog_authority_key_id(normalized_home),
        "sequence": sequence,
        "issuedAt": issued_at_text,
    }
    approved = copy.deepcopy(catalog)
    approved["approvalAttestation"] = {
        **metadata,
        "signature": "",
    }
    payload, _ = catalog_approval_payload(
        policy_digest=policy_digest,
        profile_digest=profile_digest,
        catalog=approved,
    )
    approved["approvalAttestation"]["signature"] = authority_seal(
        normalized_home,
        PERSONAL_CATALOG_APPROVAL_PURPOSE,
        _personal_catalog_seal_payload(payload, binding),
    )
    _verify_personal_catalog_approval(
        normalized_home,
        policy_digest=policy_digest,
        profile=profile,
        catalog=approved,
        now=issued_at,
        binding=binding,
    )
    return approved


def verify_catalog_approval(
    home: Path,
    *,
    policy_digest: str,
    profile: dict[str, Any],
    catalog: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Dispatch by sealed profile authority; never fall back across algorithms."""

    profile_id = profile.get("profileId") if isinstance(profile, dict) else None
    if not isinstance(profile_id, str):
        raise CatalogAuthorityError(
            "Catalog approval verification requires one exact profileId."
        )
    binding = _load_personal_profile_authority(
        home.expanduser().absolute(),
        profile_id,
        missing_ok=True,
    )
    if binding is not None:
        return _verify_personal_catalog_approval(
            home.expanduser().absolute(),
            policy_digest=policy_digest,
            profile=profile,
            catalog=catalog,
            now=now,
            binding=binding,
        )
    return _external_catalog_approval_verifier(
        home,
        policy_digest=policy_digest,
        profile=profile,
        catalog=catalog,
        now=now,
    )

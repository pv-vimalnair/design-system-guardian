
"""Create-once host trust anchor and immutable-policy verification."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .authority import (
    AUTHORITY_KEY_BYTES,
    AuthorityIntegrityError,
    authority_seal_with_key,
    harden_authority_key_permissions,
    verify_authority_key_file,
)
from .canonical import atomic_write_bytes, atomic_write_json, read_canonical_json, read_json, sha256_digest
from .catalog_authority import (
    CATALOG_AUTHORITY_BINDING_PURPOSE,
    CatalogAuthorityError,
    catalog_authority_binding_payload,
    read_catalog_authority_public_key,
    verify_pinned_catalog_authority,
    verify_runtime_dependency,
)
from .errors import PolicyIntegrityError
from .paths import (
    GuardianPaths,
    PathIntegrityError,
    assert_guardian_storage_path,
    default_guardian_home,
)


EXPECTED_POLICY_SHA256 = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
TRUST_SCHEMA_VERSION = 2


class PolicyInstallation(str):
    """Digest-compatible result that records whether this call created the anchor."""

    digest: str
    created: bool
    catalog_authority_key_id: str

    def __new__(
        cls, digest: str, *, created: bool, catalog_authority_key_id: str
    ) -> "PolicyInstallation":
        value = str.__new__(cls, digest)
        value.digest = digest
        value.created = created
        value.catalog_authority_key_id = catalog_authority_key_id
        return value


def shipped_policy_path() -> Path:
    return Path(__file__).resolve().parents[1] / "policy" / "policy-v1.json"


def shipped_policy() -> dict[str, Any]:
    try:
        value = read_json(shipped_policy_path())
    except (OSError, ValueError, UnicodeError) as error:
        raise PolicyIntegrityError(f"Shipped immutable policy cannot be read: {error}") from error
    if not isinstance(value, dict):
        raise PolicyIntegrityError("Shipped immutable policy must be a JSON object.")
    return value


def _verify_shipped_policy() -> dict[str, Any]:
    value = shipped_policy()
    digest = sha256_digest(value)
    if digest != EXPECTED_POLICY_SHA256:
        raise PolicyIntegrityError(
            "Shipped immutable policy digest does not match the compiled policy contract."
        )
    return value


def _paths(home: Path | None) -> GuardianPaths:
    return GuardianPaths((home or default_guardian_home()).expanduser().absolute())


def _reject_redirected_paths(paths: GuardianPaths) -> None:
    try:
        for target in (
            paths.trust,
            paths.policy,
            paths.policy_seal,
            paths.snapshot_authority_key,
            paths.catalog_authority_public_key,
            paths.catalog_authority_binding,
        ):
            assert_guardian_storage_path(paths.home, target)
    except PathIntegrityError as error:
        raise PolicyIntegrityError(str(error)) from error


def _existing_anchor_state(paths: GuardianPaths) -> str:
    anchor_exists = paths.policy.is_file()
    seal_exists = paths.policy_seal.is_file()
    key_exists = paths.snapshot_authority_key.is_file()
    catalog_key_exists = paths.catalog_authority_public_key.is_file()
    catalog_binding_exists = paths.catalog_authority_binding.is_file()
    if (
        anchor_exists
        and seal_exists
        and key_exists
        and catalog_key_exists
        and catalog_binding_exists
    ):
        return "complete"
    if anchor_exists and seal_exists:
        return "incompatible"
    if (
        paths.trust.exists()
        or anchor_exists
        or seal_exists
        or key_exists
        or catalog_key_exists
        or catalog_binding_exists
    ):
        return "partial"
    return "absent"


def install_policy_anchor(
    home: Path | None = None,
    *,
    catalog_authority_public_key: Path | None = None,
) -> PolicyInstallation:
    """Transactionally create policy, seals, and both distinct authorities once."""

    try:
        policy = _verify_shipped_policy()
        verify_runtime_dependency()
        paths = _paths(home)
        _reject_redirected_paths(paths)
        state = _existing_anchor_state(paths)
        if state == "complete":
            digest = verify_policy_anchor(paths.home)
            _, pinned_key_id = verify_pinned_catalog_authority(paths.home)
            if catalog_authority_public_key is not None:
                _, supplied_key_id = read_catalog_authority_public_key(
                    catalog_authority_public_key
                )
                if supplied_key_id != pinned_key_id:
                    raise PolicyIntegrityError(
                        "Supplied catalog authority differs from the immutable pinned authority."
                    )
            return PolicyInstallation(
                digest,
                created=False,
                catalog_authority_key_id=pinned_key_id,
            )
        if state == "incompatible":
            raise PolicyIntegrityError(
                "The pre-release trust anchor is incompatible with trust schema v2; "
                "Guardian will not self-enroll a catalog authority beside existing trust evidence."
            )
        if state == "partial":
            raise PolicyIntegrityError(
                "A partial policy anchor exists; Guardian will not overwrite or repair it automatically."
            )
        if catalog_authority_public_key is None:
            raise PolicyIntegrityError(
                "A new trust anchor requires --catalog-authority-public-key with an Ed25519 public PEM."
            )
        canonical_public_pem, catalog_key_id = read_catalog_authority_public_key(
            catalog_authority_public_key
        )

        paths.home.mkdir(parents=True, exist_ok=True)
        _reject_redirected_paths(paths)
        stage = Path(tempfile.mkdtemp(prefix=".trust.", dir=paths.home))
        promoted = False
        try:
            atomic_write_json(stage / "policy-v1.json", policy)
            atomic_write_bytes(
                stage / "policy-v1.sha256",
                (EXPECTED_POLICY_SHA256 + "\n").encode("ascii"),
            )
            authority_key = os.urandom(AUTHORITY_KEY_BYTES)
            atomic_write_bytes(
                stage / "snapshot-authority-v1.key",
                authority_key,
            )
            harden_authority_key_permissions(stage / "snapshot-authority-v1.key")
            atomic_write_bytes(
                stage / "catalog-authority-ed25519.pem",
                canonical_public_pem,
            )
            binding_unsigned = catalog_authority_binding_payload(
                canonical_public_pem,
                catalog_key_id,
            )
            atomic_write_json(
                stage / "catalog-authority-ed25519.binding.json",
                {
                    **binding_unsigned,
                    "authoritySeal": authority_seal_with_key(
                        authority_key,
                        CATALOG_AUTHORITY_BINDING_PURPOSE,
                        binding_unsigned,
                    ),
                },
            )
            try:
                os.rename(stage, paths.trust)
                promoted = True
            except OSError:
                if _existing_anchor_state(paths) == "complete":
                    digest = verify_policy_anchor(paths.home)
                    _, pinned_key_id = verify_pinned_catalog_authority(paths.home)
                    if pinned_key_id != catalog_key_id:
                        raise PolicyIntegrityError(
                            "Concurrent trust installation pinned a different catalog authority."
                        )
                    return PolicyInstallation(
                        digest,
                        created=False,
                        catalog_authority_key_id=pinned_key_id,
                    )
                raise
        finally:
            if not promoted and stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
        digest = verify_policy_anchor(paths.home)
        return PolicyInstallation(
            digest,
            created=True,
            catalog_authority_key_id=catalog_key_id,
        )
    except PolicyIntegrityError:
        raise
    except (AuthorityIntegrityError, CatalogAuthorityError, PathIntegrityError) as error:
        raise PolicyIntegrityError(f"Immutable policy authority is invalid: {error}") from error
    except OSError as error:
        raise PolicyIntegrityError(f"Immutable policy anchor operation failed: {error}") from error

def verify_policy_anchor(home: Path | None = None) -> str:
    """Fail closed unless policy, public seal, and private authority all agree."""

    try:
        _verify_shipped_policy()
        paths = _paths(home)
        _reject_redirected_paths(paths)
        state = _existing_anchor_state(paths)
        if state == "incompatible":
            raise PolicyIntegrityError(
                "The pre-release trust anchor is incompatible with trust schema v2."
            )
        if state != "complete":
            raise PolicyIntegrityError(
                "Immutable policy anchor is missing. Run `guardian doctor --install-policy` once."
            )
        try:
            value = read_canonical_json(paths.policy)
            seal = paths.policy_seal.read_text(encoding="ascii").strip()
        except (OSError, ValueError, UnicodeError) as error:
            raise PolicyIntegrityError(f"Immutable policy anchor cannot be read: {error}") from error
        if not isinstance(value, dict):
            raise PolicyIntegrityError("Immutable policy anchor must be a JSON object.")
        digest = sha256_digest(value)
        if seal != EXPECTED_POLICY_SHA256 or digest != seal:
            raise PolicyIntegrityError("Immutable policy anchor or seal was changed; execution is blocked.")
        verify_authority_key_file(paths.home)
        verify_pinned_catalog_authority(paths.home)
        _reject_redirected_paths(paths)
        return digest
    except PolicyIntegrityError:
        raise
    except (AuthorityIntegrityError, CatalogAuthorityError, PathIntegrityError) as error:
        raise PolicyIntegrityError(f"Immutable policy authority is invalid: {error}") from error
    except OSError as error:
        raise PolicyIntegrityError(f"Immutable policy verification failed: {error}") from error

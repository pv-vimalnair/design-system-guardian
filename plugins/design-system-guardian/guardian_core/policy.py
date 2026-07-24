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
    verify_authority_seal,
    verify_authority_key_file,
)
from .canonical import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    read_canonical_json,
    read_json,
    sha256_digest,
)
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
from .storage import exclusive_write_json


EXPECTED_POLICY_SHA256 = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
TRUST_SCHEMA_VERSION = 2
ELO_LEDGER_MODEL = "guardian-weighted-elo-v1"
ELO_ENROLLMENT_NAME = "elo-enrollment.sealed.json"
ELO_ENROLLMENT_PURPOSE = "elo-enrollment:v1"
ELO_LEDGER_MARKER_NAME = "elo-ledger-init.sealed.json"
ELO_LEDGER_HEAD_NAME = "elo-head.sealed.json"
ELO_LEDGER_MARKER_PURPOSE = "elo-ledger-init:v1"
ELO_LEDGER_HEAD_PURPOSE = "elo-head:v1"
ELO_GENESIS_SCORE = 1
_ELO_ENROLLMENT_KEYS = {
    "schemaVersion",
    "model",
    "ledgerId",
    "enrolledFrom",
    "authoritySeal",
}
_ELO_ENROLLMENT_SOURCES = {"fresh-install", "legacy-0.2-migration"}
_LEGACY_TRUST_FILES = {
    "catalog-authority-ed25519.binding.json",
    "catalog-authority-ed25519.pem",
    "policy-v1.json",
    "policy-v1.sha256",
    "snapshot-authority-v1.key",
}


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


def _elo_anchors_with_key(
    authority_key: bytes, ledger_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    marker_unsigned = {
        "schemaVersion": 1,
        "model": ELO_LEDGER_MODEL,
        "ledgerId": ledger_id,
    }
    head_unsigned = {
        "schemaVersion": 1,
        "model": ELO_LEDGER_MODEL,
        "ledgerId": ledger_id,
        "sequence": 0,
        "entryDigest": None,
        "score": ELO_GENESIS_SCORE,
        "suiteDigest": None,
    }
    return (
        {
            **marker_unsigned,
            "authoritySeal": authority_seal_with_key(
                authority_key, ELO_LEDGER_MARKER_PURPOSE, marker_unsigned
            ),
        },
        {
            **head_unsigned,
            "authoritySeal": authority_seal_with_key(
                authority_key, ELO_LEDGER_HEAD_PURPOSE, head_unsigned
            ),
        },
    )


def _initial_elo_anchors(authority_key: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    return _elo_anchors_with_key(authority_key, sha256_digest(os.urandom(32)))


def _elo_enrollment_with_key(
    authority_key: bytes, ledger_id: str, *, enrolled_from: str
) -> dict[str, Any]:
    unsigned = {
        "schemaVersion": 1,
        "model": ELO_LEDGER_MODEL,
        "ledgerId": ledger_id,
        "enrolledFrom": enrolled_from,
    }
    return {
        **unsigned,
        "authoritySeal": authority_seal_with_key(
            authority_key, ELO_ENROLLMENT_PURPOSE, unsigned
        ),
    }


def _legacy_elo_ledger_id(paths: GuardianPaths) -> str:
    return sha256_digest(
        {
            "domain": "guardian-legacy-elo-ledger-id-v1",
            "trustFiles": [
                {
                    "name": name,
                    "digest": sha256_digest((paths.trust / name).read_bytes()),
                }
                for name in sorted(_LEGACY_TRUST_FILES)
            ],
        }
    )


def _legacy_artifact_write_state(path: Path, expected: dict[str, Any]) -> str:
    metadata = path.lstat()
    if not path.is_file() or metadata.st_nlink != 1:
        return "unsafe"
    actual_bytes = path.read_bytes()
    expected_bytes = canonical_json_bytes(expected)
    if actual_bytes == expected_bytes:
        return "exact"
    if len(actual_bytes) < len(expected_bytes) and expected_bytes.startswith(
        actual_bytes
    ):
        return "partial"
    return "conflict"


def verify_elo_enrollment(home: Path, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ELO_ENROLLMENT_KEYS:
        raise PolicyIntegrityError(
            "Elo enrollment receipt has unknown or missing fields."
        )
    unsigned = {key: item for key, item in value.items() if key != "authoritySeal"}
    try:
        verify_authority_seal(
            home, ELO_ENROLLMENT_PURPOSE, unsigned, value.get("authoritySeal")
        )
    except AuthorityIntegrityError as error:
        raise PolicyIntegrityError(
            f"Elo enrollment receipt seal is invalid: {error}"
        ) from error
    ledger_id = value.get("ledgerId")
    if (
        value.get("schemaVersion") != 1
        or value.get("model") != ELO_LEDGER_MODEL
        or value.get("enrolledFrom") not in _ELO_ENROLLMENT_SOURCES
        or not isinstance(ledger_id, str)
        or len(ledger_id) != 64
        or any(character not in "0123456789abcdef" for character in ledger_id)
    ):
        raise PolicyIntegrityError("Elo enrollment receipt identity is invalid.")
    return dict(value)


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
            paths.trust / ELO_ENROLLMENT_NAME,
            paths.trust / ELO_LEDGER_MARKER_NAME,
            paths.trust / ELO_LEDGER_HEAD_NAME,
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
            marker, genesis_head = _initial_elo_anchors(authority_key)
            enrollment = _elo_enrollment_with_key(
                authority_key, marker["ledgerId"], enrolled_from="fresh-install"
            )
            atomic_write_json(stage / ELO_ENROLLMENT_NAME, enrollment)
            atomic_write_json(stage / ELO_LEDGER_MARKER_NAME, marker)
            atomic_write_json(stage / ELO_LEDGER_HEAD_NAME, genesis_head)
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


def migrate_legacy_elo_genesis(home: Path | None = None) -> bool:
    """Explicitly enroll one exact pre-Elo 0.2 trust home at score-one genesis."""

    try:
        paths = _paths(home)
        _reject_redirected_paths(paths)
        if _existing_anchor_state(paths) != "complete":
            raise PolicyIntegrityError(
                "Legacy Elo migration requires one complete five-file trust anchor."
            )
        verify_policy_anchor(paths.home)
        enrollment_path = assert_guardian_storage_path(
            paths.home, paths.trust / ELO_ENROLLMENT_NAME
        )
        marker_path = assert_guardian_storage_path(
            paths.home, paths.trust / ELO_LEDGER_MARKER_NAME
        )
        head_path = assert_guardian_storage_path(
            paths.home, paths.trust / ELO_LEDGER_HEAD_NAME
        )
        elo_root = assert_guardian_storage_path(
            paths.home, paths.home / "evolution" / "elo"
        )
        anchor_names = (
            ELO_ENROLLMENT_NAME,
            ELO_LEDGER_MARKER_NAME,
            ELO_LEDGER_HEAD_NAME,
        )
        allowed_entry_sets = {
            frozenset(_LEGACY_TRUST_FILES | set(anchor_names[:count]))
            for count in range(len(anchor_names) + 1)
        }
        trust_entries = tuple(paths.trust.iterdir())
        trust_entry_names = frozenset(path.name for path in trust_entries)
        if (
            trust_entry_names not in allowed_entry_sets
            or any(not path.is_file() for path in trust_entries)
        ):
            raise PolicyIntegrityError(
                "Legacy Elo migration requires an exact allowed trust entry set; "
                "unknown files and out-of-order anchors are blocked."
            )
        authority_key = paths.snapshot_authority_key.read_bytes()
        legacy_ledger_id = _legacy_elo_ledger_id(paths)
        legacy_marker, legacy_head = _elo_anchors_with_key(
            authority_key, legacy_ledger_id
        )
        legacy_enrollment = _elo_enrollment_with_key(
            authority_key,
            legacy_ledger_id,
            enrolled_from="legacy-0.2-migration",
        )

        if enrollment_path.exists():
            enrollment_state = _legacy_artifact_write_state(
                enrollment_path, legacy_enrollment
            )
            if enrollment_state == "unsafe":
                raise PolicyIntegrityError(
                    "Elo enrollment receipt is not a single-link regular file."
                )
            if enrollment_state == "partial":
                if marker_path.exists() or head_path.exists() or elo_root.exists():
                    raise PolicyIntegrityError(
                        "Partial Elo enrollment conflicts with later migration evidence."
                    )
                enrollment_path.unlink()

        if enrollment_path.exists():
            enrollment = verify_elo_enrollment(
                paths.home, read_canonical_json(enrollment_path)
            )
            if (
                enrollment["enrolledFrom"] == "legacy-0.2-migration"
                and enrollment_state != "exact"
            ):
                raise PolicyIntegrityError(
                    "Legacy Elo enrollment is not the exact deterministic receipt."
                )
            if enrollment["enrolledFrom"] != "legacy-0.2-migration":
                if not marker_path.is_file() or not head_path.is_file():
                    raise PolicyIntegrityError(
                        "Elo enrollment receipt proves marker or head deletion; migration is blocked."
                    )
                expected_marker, expected_head = _elo_anchors_with_key(
                    authority_key, enrollment["ledgerId"]
                )
                if (
                    read_canonical_json(marker_path) != expected_marker
                    or read_canonical_json(head_path) != expected_head
                ):
                    raise PolicyIntegrityError(
                        "Existing Elo enrollment does not match its protected genesis anchors."
                    )
                raise PolicyIntegrityError(
                    "Elo enrollment was created by a fresh 0.3 installation; "
                    "it is not a legacy 0.2 migration."
                )
            expected_marker, expected_head = _elo_anchors_with_key(
                authority_key, enrollment["ledgerId"]
            )
            if elo_root.exists():
                raise PolicyIntegrityError(
                    "Legacy Elo migration cannot repair or reset existing ledger evidence."
                )
            changed = False
            targets = (
                (marker_path, expected_marker),
                (head_path, expected_head),
            )
            for index, (target, expected) in enumerate(targets):
                later_paths = tuple(path for path, _ in targets[index + 1 :])
                if target.exists():
                    state = _legacy_artifact_write_state(target, expected)
                    if state == "exact":
                        continue
                    if state == "partial" and not any(
                        path.exists() for path in later_paths
                    ):
                        target.unlink()
                        exclusive_write_json(paths.home, target, expected)
                        changed = True
                    else:
                        raise PolicyIntegrityError(
                            "Interrupted legacy Elo migration contains conflicting anchor evidence."
                        )
                else:
                    if any(path.exists() for path in later_paths):
                        raise PolicyIntegrityError(
                            "Legacy Elo migration anchor deletion conflicts with later evidence."
                        )
                    exclusive_write_json(paths.home, target, expected)
                    changed = True
            return changed

        if marker_path.exists() or head_path.exists() or elo_root.exists():
            raise PolicyIntegrityError(
                "Existing Elo marker, head, or ledger evidence proves deletion or prior enrollment; migration is blocked."
            )
        trust_entries = tuple(paths.trust.iterdir())
        if (
            {path.name for path in trust_entries} != _LEGACY_TRUST_FILES
            or any(not path.is_file() for path in trust_entries)
        ):
            raise PolicyIntegrityError(
                "Legacy Elo migration accepts only the exact five-file 0.2 trust layout."
            )
        marker = legacy_marker
        head = legacy_head
        enrollment = legacy_enrollment
        exclusive_write_json(paths.home, enrollment_path, enrollment)
        exclusive_write_json(paths.home, marker_path, marker)
        exclusive_write_json(paths.home, head_path, head)
        if (
            verify_elo_enrollment(paths.home, read_canonical_json(enrollment_path))
            != enrollment
            or read_canonical_json(marker_path) != marker
            or read_canonical_json(head_path) != head
        ):
            raise PolicyIntegrityError(
                "Legacy Elo migration failed complete post-write verification."
            )
        return True
    except PolicyIntegrityError:
        raise
    except (AuthorityIntegrityError, CatalogAuthorityError, PathIntegrityError) as error:
        raise PolicyIntegrityError(f"Legacy Elo migration authority is invalid: {error}") from error
    except (OSError, UnicodeError, ValueError) as error:
        raise PolicyIntegrityError(f"Legacy Elo migration failed safely: {error}") from error


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

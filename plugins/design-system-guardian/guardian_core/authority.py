"""Host-owned HMAC authority for immutable snapshots and task pins."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path, is_link_or_reparse


AUTHORITY_KEY_BYTES = 32
AUTHORITY_KEY_ID = "snapshot-authority-v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = b"design-system-guardian\0snapshot-authority-v1\0"


class AuthorityIntegrityError(ValueError):
    """Raised when the private authority or a seal is invalid."""


def harden_authority_key_permissions(path: Path) -> None:
    """Use owner-only POSIX mode; Windows ACL inheritance is outside stdlib reach."""

    os.chmod(path, 0o600)


def verify_authority_key_file(home: Path) -> None:
    paths = GuardianPaths(home.expanduser().absolute())
    try:
        key_path = assert_guardian_storage_path(paths.home, paths.snapshot_authority_key)
    except PathIntegrityError as error:
        raise AuthorityIntegrityError(str(error)) from error
    if is_link_or_reparse(key_path):
        raise AuthorityIntegrityError("Snapshot authority key may not be redirected.")
    try:
        metadata = key_path.lstat()
    except OSError as error:
        raise AuthorityIntegrityError(f"Snapshot authority key is missing or unreadable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthorityIntegrityError("Snapshot authority key must be a regular file.")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AuthorityIntegrityError("Snapshot authority key permissions must be owner-only (0600).")
    try:
        key = key_path.read_bytes()
    except OSError as error:
        raise AuthorityIntegrityError(f"Snapshot authority key cannot be read: {error}") from error
    if len(key) != AUTHORITY_KEY_BYTES:
        raise AuthorityIntegrityError("Snapshot authority key has an invalid length.")
    assert_guardian_storage_path(paths.home, key_path)


def _load_key(home: Path) -> bytes:
    verify_authority_key_file(home)
    return GuardianPaths(home.expanduser().absolute()).snapshot_authority_key.read_bytes()


def authority_seal(home: Path, purpose: str, payload: Any) -> str:
    return authority_seal_with_key(_load_key(home), purpose, payload)


def authority_seal_with_key(key: bytes, purpose: str, payload: Any) -> str:
    """Seal payload with already-generated create-once authority key material."""

    if not isinstance(key, bytes) or len(key) != AUTHORITY_KEY_BYTES:
        raise AuthorityIntegrityError("Snapshot authority key has an invalid length.")
    if not isinstance(purpose, str) or not purpose or "\0" in purpose:
        raise AuthorityIntegrityError("Authority seal purpose must be a non-empty domain string.")
    message = _DOMAIN + purpose.encode("ascii", "strict") + b"\0" + canonical_json_bytes(payload)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_authority_seal(home: Path, purpose: str, payload: Any, claimed: Any) -> None:
    if not isinstance(claimed, str) or not _HEX_64.fullmatch(claimed):
        raise AuthorityIntegrityError("Authority seal must be an exact lowercase SHA-256 HMAC.")
    expected = authority_seal(home, purpose, payload)
    if not hmac.compare_digest(expected, claimed):
        raise AuthorityIntegrityError("Immutable artifact authority seal does not match trusted host evidence.")


"""Profile-isolated host state paths and redirection defenses."""

from __future__ import annotations

import ctypes
import importlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


PROFILE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class PathIntegrityError(ValueError):
    """Raised when host-owned state escapes containment or uses redirection."""


class _WindowsGuid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


_FOLDERID_PROFILE = _WindowsGuid(
    0x5E6C858F,
    0x0E22,
    0x4760,
    (ctypes.c_ubyte * 8)(0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73),
)


def _windows_profile_home() -> Path:
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    except (AttributeError, OSError) as error:
        raise PathIntegrityError(
            f"Windows account profile API is unavailable: {error}"
        ) from error
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(_WindowsGuid),
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None
    pointer = ctypes.c_void_p()
    result = shell32.SHGetKnownFolderPath(
        ctypes.byref(_FOLDERID_PROFILE),
        0,
        None,
        ctypes.byref(pointer),
    )
    if result != 0 or not pointer.value:
        raise PathIntegrityError(
            "Windows Known Folder API could not resolve the signed-in account profile "
            f"(HRESULT 0x{result & 0xFFFFFFFF:08x})."
        )
    try:
        value = ctypes.wstring_at(pointer.value)
    finally:
        ole32.CoTaskMemFree(pointer)
    if not value:
        raise PathIntegrityError("Windows account profile path is empty.")
    return Path(value)


def _posix_profile_home() -> Path:
    try:
        pwd = importlib.import_module("pwd")
        value = pwd.getpwuid(os.getuid()).pw_dir
    except (AttributeError, ImportError, KeyError, OSError) as error:
        raise PathIntegrityError(
            f"POSIX account database could not resolve the effective account profile: {error}"
        ) from error
    if not isinstance(value, str) or not value:
        raise PathIntegrityError("POSIX account profile path is empty.")
    return Path(value)


def _account_profile_home() -> Path:
    return _windows_profile_home() if os.name == "nt" else _posix_profile_home()


def _validated_account_profile_home() -> Path:
    profile = _account_profile_home()
    if not profile.is_absolute():
        raise PathIntegrityError("OS account profile path must be absolute.")
    try:
        metadata = profile.lstat()
    except OSError as error:
        raise PathIntegrityError(
            f"OS account profile path is missing or unreadable: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise PathIntegrityError("OS account profile path must be a directory.")
    for candidate in (profile, *profile.parents):
        if is_link_or_reparse(candidate):
            raise PathIntegrityError(
                f"OS account profile path may not use redirection: {candidate}"
            )
    return profile


def default_guardian_home() -> Path:
    profile = _validated_account_profile_home()
    guardian_home = profile / ".design-system-guardian"
    return assert_guardian_storage_path(profile, guardian_home)


def validate_profile_id(profile_id: str) -> str:
    if not PROFILE_ID_PATTERN.fullmatch(profile_id):
        raise ValueError(
            "Profile IDs must be 1-63 lowercase ASCII letters, digits, or hyphens, "
            "must start with a letter, and cannot contain path separators."
        )
    return profile_id


@dataclass(frozen=True)
class GuardianPaths:
    home: Path

    @property
    def trust(self) -> Path:
        return self.home / "trust"

    @property
    def policy(self) -> Path:
        return self.trust / "policy-v1.json"

    @property
    def policy_seal(self) -> Path:
        return self.trust / "policy-v1.sha256"

    @property
    def snapshot_authority_key(self) -> Path:
        return self.trust / "snapshot-authority-v1.key"

    @property
    def catalog_authority_public_key(self) -> Path:
        return self.trust / "catalog-authority-ed25519.pem"

    @property
    def catalog_authority_binding(self) -> Path:
        return self.trust / "catalog-authority-ed25519.binding.json"

    @property
    def evolution(self) -> Path:
        return self.home / "evolution"

    @property
    def elo(self) -> Path:
        return self.evolution / "elo"

    @property
    def elo_history(self) -> Path:
        return self.elo / "history"

    @property
    def profiles(self) -> Path:
        return self.home / "profiles"

    def profile(self, profile_id: str) -> Path:
        return self.profiles / validate_profile_id(profile_id)

    def snapshots(self, profile_id: str) -> Path:
        return self.profile(profile_id) / "snapshots"

    def audits(self, profile_id: str) -> Path:
        return self.profile(profile_id) / "audits"

    def migrations(self, profile_id: str) -> Path:
        return self.profile(profile_id) / "migrations"


def is_link_or_reparse(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse points."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def assert_guardian_storage_path(home: Path, target: Path) -> Path:
    """Lexically contain target and reject every existing redirected path segment."""

    normalized_home = home.expanduser().absolute()
    normalized_target = target.expanduser().absolute()
    try:
        relative = normalized_target.relative_to(normalized_home)
    except ValueError as error:
        raise PathIntegrityError("Guardian storage path escapes the configured home.") from error

    candidates: list[Path] = [normalized_home, *normalized_home.parents]
    current = normalized_home
    for part in relative.parts:
        current = current / part
        candidates.append(current)
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if is_link_or_reparse(candidate):
            raise PathIntegrityError(
                f"Guardian storage may not use a symlink, junction, or reparse point: {candidate}"
            )
    return normalized_target

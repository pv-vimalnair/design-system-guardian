"""Strict company-profile validation and profile-isolated storage."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .canonical import read_canonical_json
from .flutter_packages import (
    FlutterPackageProvenanceError,
    validate_required_package_bindings,
)
from .flutter_toolchain import FlutterToolchainIntegrityError, select_profile_toolchain
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path, validate_profile_id
from .storage import contained_atomic_write_json


class ProfileValidationError(ValueError):
    """Raised when a company profile is invalid or unsafe to blend."""


_PROFILE_KEYS = {"schemaVersion", "profileId", "displayName", "figma", "adapters"}
_FIGMA_KEYS = {"allowlistedLibraryFiles"}
_LIBRARY_KEYS = {"fileKey", "name"}
_FLUTTER_ENABLED_KEYS = {"enabled", "platformArtifacts", "requiredPackages"}


def _exact_keys(value: dict[str, Any], allowed: set[str], required: set[str], path: str) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise ProfileValidationError(f"Unknown properties at {path}: {sorted(unknown)!r}.")
    if missing:
        raise ProfileValidationError(f"Missing required properties at {path}: {sorted(missing)!r}.")


def validate_profile(document: Any) -> dict[str, Any]:
    """Return a detached profile only when its full shape is valid."""

    if not isinstance(document, dict):
        raise ProfileValidationError("A company profile must be a JSON object.")
    _exact_keys(document, _PROFILE_KEYS, _PROFILE_KEYS, "profile")
    if document.get("schemaVersion") != 1:
        raise ProfileValidationError("Profile schemaVersion must be exactly 1.")
    try:
        validate_profile_id(document.get("profileId"))
    except (TypeError, ValueError) as error:
        raise ProfileValidationError(str(error)) from error
    if not isinstance(document.get("displayName"), str) or not document["displayName"].strip():
        raise ProfileValidationError("Profile displayName must be a non-empty string.")
    figma = document.get("figma")
    if not isinstance(figma, dict):
        raise ProfileValidationError("Profile figma configuration must be an object.")
    _exact_keys(figma, _FIGMA_KEYS, _FIGMA_KEYS, "profile.figma")
    libraries = figma.get("allowlistedLibraryFiles")
    if not isinstance(libraries, list) or not libraries:
        raise ProfileValidationError("At least one Figma library file must be explicitly allowlisted.")
    seen: set[str] = set()
    for index, library in enumerate(libraries):
        if not isinstance(library, dict):
            raise ProfileValidationError(f"Library entry {index} must be an object.")
        _exact_keys(library, _LIBRARY_KEYS, {"fileKey"}, f"profile.figma.allowlistedLibraryFiles[{index}]")
        file_key = library.get("fileKey")
        if not isinstance(file_key, str) or not file_key.strip():
            raise ProfileValidationError(f"Library entry {index} needs a non-empty exact fileKey.")
        if file_key in seen:
            raise ProfileValidationError(f"Duplicate allowlisted Figma fileKey: {file_key!r}.")
        seen.add(file_key)
        if "name" in library and not isinstance(library["name"], str):
            raise ProfileValidationError(f"Library entry {index} name must be a string.")
    adapters = document.get("adapters")
    if not isinstance(adapters, dict) or any(not isinstance(value, dict) for value in adapters.values()):
        raise ProfileValidationError("Profile adapters must map adapter IDs to configuration objects.")
    flutter = adapters.get("flutter")
    if flutter is not None:
        enabled = flutter.get("enabled")
        if enabled is False:
            _exact_keys(flutter, {"enabled"}, {"enabled"}, "profile.adapters.flutter")
        elif enabled is True:
            _exact_keys(
                flutter,
                _FLUTTER_ENABLED_KEYS,
                _FLUTTER_ENABLED_KEYS,
                "profile.adapters.flutter",
            )
            try:
                select_profile_toolchain(flutter["platformArtifacts"])
                validate_required_package_bindings(flutter["requiredPackages"])
            except (
                FlutterPackageProvenanceError,
                FlutterToolchainIntegrityError,
            ) as error:
                raise ProfileValidationError(str(error)) from error
        else:
            raise ProfileValidationError(
                "profile.adapters.flutter.enabled must be exactly true or false."
            )
    return copy.deepcopy(document)


def profile_path(home: Path, profile_id: str) -> Path:
    normalized_home = home.expanduser().absolute()
    try:
        path = GuardianPaths(normalized_home).profile(profile_id) / "profile.json"
        return assert_guardian_storage_path(normalized_home, path)
    except (PathIntegrityError, ValueError) as error:
        raise ProfileValidationError(str(error)) from error


def install_profile(home: Path, document: Any) -> Path:
    """Atomically install or update one profile without touching another profile ID."""

    profile = validate_profile(document)
    path = profile_path(home, profile["profileId"])
    try:
        contained_atomic_write_json(home.expanduser().absolute(), path, profile)
        profile_path(home, profile["profileId"])
    except (OSError, PathIntegrityError) as error:
        raise ProfileValidationError(f"Profile storage is unsafe or unavailable: {error}") from error
    return path


def load_profile(home: Path, profile_id: str) -> dict[str, Any]:
    """Load a canonical profile from its isolated profile directory."""

    path = profile_path(home, profile_id)
    try:
        profile = read_canonical_json(path)
        profile_path(home, profile_id)
    except (OSError, ValueError, UnicodeError) as error:
        raise ProfileValidationError(f"Profile {profile_id!r} cannot be read canonically: {error}") from error
    validated = validate_profile(profile)
    if validated["profileId"] != profile_id:
        raise ProfileValidationError("Stored profile identity does not match its isolated path.")
    return validated

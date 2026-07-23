"""Profile-bound Dart SDK artifact verification and isolated staging."""

from __future__ import annotations

import copy
import hashlib
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .canonical import sha256_digest
from .paths import is_link_or_reparse


DART_SDK_CONTENT_ALGORITHM = "design-system-guardian.dart-sdk-content.v1"
SUPPORTED_PLATFORM_IDS = {
    "windows-x64",
    "windows-arm64",
    "linux-x64",
    "linux-arm64",
    "macos-x64",
    "macos-arm64",
}

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BINDING_KEYS = {"platformId", "dartSdk"}
_SDK_BINDING_KEYS = {"contentDigest", "executableRelativePath"}
_EVIDENCE_KEYS = {
    "schemaVersion",
    "algorithm",
    "platformId",
    "canonicalRoot",
    "rootIdentity",
    "executableRelativePath",
    "contentDigest",
    "files",
    "fileManifestDigest",
}


class FlutterToolchainIntegrityError(ValueError):
    """A Dart SDK artifact is malformed, redirected, or not profile-bound."""


class FlutterToolchainUnsupportedError(FlutterToolchainIntegrityError):
    """The current host platform has no supported profile-bound Dart SDK."""


def current_platform_id() -> str:
    operating_system = {
        "win32": "windows",
        "linux": "linux",
        "darwin": "macos",
    }.get(sys.platform)
    architecture = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    if operating_system is None or architecture is None:
        raise FlutterToolchainUnsupportedError(
            "The current host platform has no supported Dart SDK artifact identity."
        )
    return f"{operating_system}-{architecture}"


def expected_dart_executable(platform_id: str) -> str:
    if platform_id not in SUPPORTED_PLATFORM_IDS:
        raise FlutterToolchainIntegrityError(
            f"Unsupported Flutter platform artifact identity: {platform_id!r}."
        )
    return "bin/dart.exe" if platform_id.startswith("windows-") else "bin/dart"


def _canonical_relative(value: Any, *, platform_id: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FlutterToolchainIntegrityError(
            "Dart SDK executableRelativePath must be a canonical POSIX path."
        )
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or value != expected_dart_executable(platform_id)
    ):
        raise FlutterToolchainIntegrityError(
            "Dart SDK executableRelativePath is not the exact platform identity."
        )
    return value


def validate_toolchain_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_KEYS:
        raise FlutterToolchainIntegrityError(
            "Flutter toolchain binding has unknown or missing fields."
        )
    platform_id = value.get("platformId")
    if platform_id not in SUPPORTED_PLATFORM_IDS:
        raise FlutterToolchainIntegrityError("Flutter toolchain platformId is unsupported.")
    dart_sdk = value.get("dartSdk")
    if not isinstance(dart_sdk, dict) or set(dart_sdk) != _SDK_BINDING_KEYS:
        raise FlutterToolchainIntegrityError(
            "Flutter toolchain dartSdk binding has unknown or missing fields."
        )
    content_digest = dart_sdk.get("contentDigest")
    if not isinstance(content_digest, str) or _DIGEST.fullmatch(content_digest) is None:
        raise FlutterToolchainIntegrityError(
            "Dart SDK contentDigest must be a lowercase SHA-256 digest."
        )
    executable_relative = _canonical_relative(
        dart_sdk.get("executableRelativePath"), platform_id=platform_id
    )
    return {
        "platformId": platform_id,
        "dartSdk": {
            "contentDigest": content_digest,
            "executableRelativePath": executable_relative,
        },
    }


def select_profile_toolchain(platform_artifacts: Any) -> dict[str, Any]:
    if not isinstance(platform_artifacts, dict) or not platform_artifacts:
        raise FlutterToolchainIntegrityError(
            "Flutter platformArtifacts must be a non-empty exact object."
        )
    normalized: dict[str, Any] = {}
    for platform_id in sorted(platform_artifacts):
        if platform_id not in SUPPORTED_PLATFORM_IDS:
            raise FlutterToolchainIntegrityError(
                f"Unsupported Flutter platform artifact identity: {platform_id!r}."
            )
        artifact = platform_artifacts[platform_id]
        if not isinstance(artifact, dict) or set(artifact) != {"dartSdk"}:
            raise FlutterToolchainIntegrityError(
                f"platformArtifacts.{platform_id} has unknown or missing fields."
            )
        normalized[platform_id] = validate_toolchain_binding(
            {"platformId": platform_id, "dartSdk": artifact["dartSdk"]}
        )["dartSdk"]
    selected = current_platform_id()
    if selected not in normalized:
        raise FlutterToolchainUnsupportedError(
            f"The selected profile has no Dart SDK artifact for {selected}."
        )
    return {"platformId": selected, "dartSdk": normalized[selected]}


def _reject_redirected_chain(path: Path, label: str) -> None:
    absolute = path.expanduser().absolute()
    for candidate in (absolute, *absolute.parents):
        if candidate.exists() and is_link_or_reparse(candidate):
            raise FlutterToolchainIntegrityError(
                f"{label} may not traverse a link, junction, or reparse point: {candidate}"
            )


def _directory(path: Path, label: str) -> Path:
    _reject_redirected_chain(path, label)
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise FlutterToolchainIntegrityError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise FlutterToolchainIntegrityError(f"{label} must be a directory.")
    return resolved


def _regular_file(path: Path, label: str) -> Path:
    _reject_redirected_chain(path, label)
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise FlutterToolchainIntegrityError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FlutterToolchainIntegrityError(f"{label} must be a regular file.")
    return resolved


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _overlaps(left: Path, right: Path) -> bool:
    return _within(left, right) or _within(right, left)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _root_identity(root: Path) -> str:
    metadata = root.stat()
    return sha256_digest(
        {
            "canonicalPath": os.path.normcase(str(root)),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    )


def dart_sdk_file_manifest(
    root: Path, *, executable_relative_path: str
) -> list[dict[str, str]]:
    canonical_root = _directory(root, "Profile-bound Dart SDK root")
    output: list[dict[str, str]] = []
    case_keys: set[str] = set()
    for directory, child_directories, names in os.walk(
        canonical_root, followlinks=False
    ):
        current = Path(directory)
        for child in list(child_directories):
            candidate = current / child
            if is_link_or_reparse(candidate):
                raise FlutterToolchainIntegrityError(
                    f"Dart SDK may not contain a redirected directory: {candidate}"
                )
        child_directories.sort()
        for name in sorted(names):
            path = current / name
            if is_link_or_reparse(path):
                raise FlutterToolchainIntegrityError(
                    f"Dart SDK may not contain a redirected file: {path}"
                )
            try:
                metadata = path.stat()
            except OSError as error:
                raise FlutterToolchainIntegrityError(
                    f"Dart SDK file is unavailable: {path}: {error}"
                ) from error
            if not stat.S_ISREG(metadata.st_mode):
                raise FlutterToolchainIntegrityError(
                    f"Dart SDK contains a non-regular artifact: {path}"
                )
            relative = path.relative_to(canonical_root).as_posix()
            folded = relative.casefold()
            if folded in case_keys:
                raise FlutterToolchainIntegrityError(
                    "Dart SDK paths collide under case folding."
                )
            case_keys.add(folded)
            output.append({"path": relative, "sha256": _sha256_file(path)})
    output.sort(key=lambda item: item["path"])
    paths = {item["path"] for item in output}
    if executable_relative_path not in paths:
        raise FlutterToolchainIntegrityError(
            "Dart SDK manifest lacks its exact profile-bound executable."
        )
    if not any(path.startswith("bin/snapshots/") for path in paths):
        raise FlutterToolchainIntegrityError(
            "Dart SDK manifest lacks analyzer/runtime snapshots."
        )
    if not any(path.startswith("lib/") and path.endswith(".dart") for path in paths):
        raise FlutterToolchainIntegrityError("Dart SDK manifest lacks SDK library sources.")
    return output


def dart_sdk_content_digest(files: Sequence[Mapping[str, str]]) -> str:
    return sha256_digest(
        {
            "schemaVersion": 1,
            "algorithm": DART_SDK_CONTENT_ALGORITHM,
            "files": list(files),
        }
    )


def _sdk_root_for_executable(executable: Path, relative: str) -> Path:
    root = executable
    for _ in PurePosixPath(relative).parts:
        root = root.parent
    return _directory(root, "Profile-bound Dart SDK root")


def prepare_dart_sdk_artifact(
    discovered_executable: Path,
    *,
    binding: Mapping[str, Any],
    product_root: Path,
) -> dict[str, Any]:
    normalized = validate_toolchain_binding(dict(binding))
    actual_platform = current_platform_id()
    if normalized["platformId"] != actual_platform:
        raise FlutterToolchainIntegrityError(
            "Flutter toolchain binding does not match the current host platform."
        )
    executable = _regular_file(discovered_executable, "Dart analyzer executable")
    relative = normalized["dartSdk"]["executableRelativePath"]
    root = _sdk_root_for_executable(executable, relative)
    expected_executable = _regular_file(
        root / PurePosixPath(relative), "Profile-bound Dart SDK executable"
    )
    if expected_executable != executable:
        raise FlutterToolchainIntegrityError(
            "PATH Dart executable does not have the profile-bound SDK-relative identity."
        )
    product = product_root.expanduser().resolve(strict=True)
    guardian_root = Path(__file__).resolve().parents[1]
    if _overlaps(root, product) or _overlaps(root, guardian_root):
        raise FlutterToolchainIntegrityError(
            "Profile-bound Dart SDK may not overlap the product or Guardian code."
        )
    files = dart_sdk_file_manifest(root, executable_relative_path=relative)
    content_digest = dart_sdk_content_digest(files)
    if content_digest != normalized["dartSdk"]["contentDigest"]:
        raise FlutterToolchainIntegrityError(
            "Dart SDK content does not match the profile-bound Dart SDK artifact."
        )
    return {
        "schemaVersion": 1,
        "algorithm": DART_SDK_CONTENT_ALGORITHM,
        "platformId": actual_platform,
        "canonicalRoot": str(root),
        "rootIdentity": _root_identity(root),
        "executableRelativePath": relative,
        "contentDigest": content_digest,
        "files": files,
        "fileManifestDigest": sha256_digest(files),
    }


def _validate_evidence_shape(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _EVIDENCE_KEYS
        or value.get("schemaVersion") != 1
        or value.get("algorithm") != DART_SDK_CONTENT_ALGORITHM
        or value.get("platformId") not in SUPPORTED_PLATFORM_IDS
        or not isinstance(value.get("canonicalRoot"), str)
        or not Path(value["canonicalRoot"]).is_absolute()
        or not isinstance(value.get("rootIdentity"), str)
        or _DIGEST.fullmatch(value["rootIdentity"]) is None
        or not isinstance(value.get("contentDigest"), str)
        or _DIGEST.fullmatch(value["contentDigest"]) is None
        or not isinstance(value.get("fileManifestDigest"), str)
        or _DIGEST.fullmatch(value["fileManifestDigest"]) is None
        or not isinstance(value.get("files"), list)
    ):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK toolchain evidence is malformed."
        )
    _canonical_relative(
        value.get("executableRelativePath"), platform_id=value["platformId"]
    )
    if value["files"] != sorted(value["files"], key=lambda item: item.get("path", "")):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK file manifest is not canonical."
        )
    if value["fileManifestDigest"] != sha256_digest(value["files"]):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK file manifest digest is mismatched."
        )
    if value["contentDigest"] != dart_sdk_content_digest(value["files"]):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK content digest is mismatched."
        )
    return value


def verify_dart_sdk_evidence(
    evidence: Any, *, product_root: Path
) -> dict[str, Any]:
    value = _validate_evidence_shape(evidence)
    root = _directory(Path(value["canonicalRoot"]), "Sealed Dart SDK root")
    if str(root) != value["canonicalRoot"]:
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK canonical root was redirected or replayed."
        )
    product = product_root.expanduser().resolve(strict=True)
    guardian_root = Path(__file__).resolve().parents[1]
    if _overlaps(root, product) or _overlaps(root, guardian_root):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK overlaps the product or Guardian code."
        )
    relative = value["executableRelativePath"]
    executable = _regular_file(
        root / PurePosixPath(relative), "Sealed Dart SDK executable"
    )
    if _sdk_root_for_executable(executable, relative) != root:
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK executable-relative identity changed."
        )
    files = dart_sdk_file_manifest(root, executable_relative_path=relative)
    if (
        _root_identity(root) != value["rootIdentity"]
        or files != value["files"]
        or sha256_digest(files) != value["fileManifestDigest"]
        or dart_sdk_content_digest(files) != value["contentDigest"]
    ):
        raise FlutterToolchainIntegrityError(
            "Sealed Dart SDK content, root, or manifest changed."
        )
    return copy.deepcopy(value)


def stage_dart_sdk_artifact(stage: Path, evidence: Mapping[str, Any]) -> Path:
    value = _validate_evidence_shape(dict(evidence))
    source_root = _directory(
        Path(value["canonicalRoot"]), "Profile-bound Dart SDK root"
    )
    destination_root = stage / ".guardian-toolchain" / "dart-sdk"
    destination_root.mkdir(parents=True)
    for item in value["files"]:
        source = _regular_file(
            source_root / PurePosixPath(item["path"]), "Dart SDK source file"
        )
        destination = destination_root / PurePosixPath(item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        shutil.copymode(source, destination)
        if _sha256_file(destination) != item["sha256"]:
            raise FlutterToolchainIntegrityError(
                "Dart SDK changed while entering host staging."
            )
    staged_files = dart_sdk_file_manifest(
        destination_root,
        executable_relative_path=value["executableRelativePath"],
    )
    if (
        staged_files != value["files"]
        or dart_sdk_content_digest(staged_files) != value["contentDigest"]
    ):
        raise FlutterToolchainIntegrityError(
            "Staged Dart SDK differs from the profile-bound artifact."
        )
    executable = _regular_file(
        destination_root / PurePosixPath(value["executableRelativePath"]),
        "Staged Dart SDK executable",
    )
    if os.name != "nt" and not os.access(executable, os.X_OK):
        raise FlutterToolchainIntegrityError(
            "Staged Dart SDK executable lacks execute permission."
        )
    return executable


__all__ = [
    "DART_SDK_CONTENT_ALGORITHM",
    "SUPPORTED_PLATFORM_IDS",
    "FlutterToolchainIntegrityError",
    "FlutterToolchainUnsupportedError",
    "current_platform_id",
    "dart_sdk_content_digest",
    "dart_sdk_file_manifest",
    "expected_dart_executable",
    "prepare_dart_sdk_artifact",
    "select_profile_toolchain",
    "stage_dart_sdk_artifact",
    "validate_toolchain_binding",
    "verify_dart_sdk_evidence",
]

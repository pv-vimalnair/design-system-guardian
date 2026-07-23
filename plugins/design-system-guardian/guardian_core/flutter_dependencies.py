"""Trusted Flutter package_config and governed dependency provenance."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import shutil
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import unquote, urlparse

from .canonical import canonical_json_bytes, decode_json_bytes, sha256_digest
from .flutter_packages import (
    PACKAGE_CONTENT_ALGORITHM,
    package_content_digest,
    valid_repository_commit,
    valid_package_name,
)
from .paths import is_link_or_reparse


class FlutterDependencyIntegrityError(ValueError):
    """A governed Dart package cannot be proven to be the approved content."""


_PACKAGE_EXCLUDED_DIRECTORIES = {
    ".dart_tool",
    ".git",
    ".idea",
    ".pub-cache",
    ".vscode",
    "build",
    "coverage",
}
_PACKAGE_CONFIG_ENTRY_KEYS = {"name", "rootUri", "packageUri", "languageVersion"}
_PUBSPEC_NAME = re.compile(r"^name:[ \t]*([a-z][a-z0-9_]*)[ \t]*(?:#.*)?$")
_WORKSPACE_MARKER = re.compile(r"^workspace:[ \t]*(?:#.*)?$", re.MULTILINE)


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


def _reject_redirected_chain(path: Path, label: str) -> None:
    absolute = path.expanduser().absolute()
    for candidate in (absolute, *absolute.parents):
        if candidate.exists() and is_link_or_reparse(candidate):
            raise FlutterDependencyIntegrityError(
                f"{label} may not traverse a symlink, junction, or reparse point: {candidate}"
            )


def _directory(path: Path, label: str) -> Path:
    _reject_redirected_chain(path, label)
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise FlutterDependencyIntegrityError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise FlutterDependencyIntegrityError(f"{label} must be a directory.")
    return resolved


def _regular_file(path: Path, label: str) -> Path:
    _reject_redirected_chain(path, label)
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise FlutterDependencyIntegrityError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FlutterDependencyIntegrityError(f"{label} must be a regular file.")
    return resolved


def _pubspec_name(root: Path, label: str) -> str:
    path = _regular_file(root / "pubspec.yaml", f"{label} pubspec.yaml")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise FlutterDependencyIntegrityError(
            f"{label} pubspec.yaml is unreadable: {error}"
        ) from error
    names = []
    for line in lines:
        if line[:1].isspace():
            continue
        match = _PUBSPEC_NAME.fullmatch(line)
        if match is not None:
            names.append(match.group(1))
    if len(names) != 1:
        raise FlutterDependencyIntegrityError(
            f"{label} pubspec.yaml must contain one canonical top-level package name."
        )
    return names[0]


def package_file_manifest(root: Path) -> list[dict[str, str]]:
    """Hash every file in a clean package artifact; reject cache/excluded dirs."""

    canonical_root = _directory(root, "Governed package root")
    output: list[dict[str, str]] = []
    case_keys: set[str] = set()
    for directory, child_directories, names in os.walk(
        canonical_root, followlinks=False
    ):
        current = Path(directory)
        for child in list(child_directories):
            candidate = current / child
            if child in _PACKAGE_EXCLUDED_DIRECTORIES:
                raise FlutterDependencyIntegrityError(
                    f"Governed package must be a clean immutable artifact; excluded/cache directory is forbidden: {candidate}"
                )
            if is_link_or_reparse(candidate):
                raise FlutterDependencyIntegrityError(
                    f"Governed package may not contain a redirected directory: {candidate}"
                )
        child_directories.sort()
        for name in sorted(names):
            path = current / name
            if is_link_or_reparse(path):
                raise FlutterDependencyIntegrityError(
                    f"Governed package may not contain a redirected file: {path}"
                )
            try:
                metadata = path.stat()
            except OSError as error:
                raise FlutterDependencyIntegrityError(
                    f"Governed package file is unavailable: {path}: {error}"
                ) from error
            if not stat.S_ISREG(metadata.st_mode):
                raise FlutterDependencyIntegrityError(
                    f"Governed package contains a non-regular artifact: {path}"
                )
            relative = path.relative_to(canonical_root).as_posix()
            folded = relative.casefold()
            if folded in case_keys:
                raise FlutterDependencyIntegrityError(
                    "Governed package paths collide under case folding."
                )
            case_keys.add(folded)
            output.append({"path": relative, "sha256": _sha256_file(path)})
    output.sort(key=lambda item: item["path"])
    if not any(item["path"] == "pubspec.yaml" for item in output):
        raise FlutterDependencyIntegrityError("Governed package manifest lacks pubspec.yaml.")
    if not any(
        item["path"].startswith("lib/") and item["path"].endswith(".dart")
        for item in output
    ):
        raise FlutterDependencyIntegrityError(
            "Governed Flutter package manifest lacks a Dart library source."
        )
    return output


def _uri_root(value: Any, package_config_path: Path, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FlutterDependencyIntegrityError(f"{label}.rootUri is malformed.")
    parsed = urlparse(value)
    if parsed.query or parsed.fragment or parsed.params:
        raise FlutterDependencyIntegrityError(f"{label}.rootUri has forbidden URI fields.")
    decoded = unquote(parsed.path)
    if parsed.scheme == "":
        if parsed.netloc or PurePosixPath(decoded).is_absolute():
            raise FlutterDependencyIntegrityError(f"{label}.rootUri is not a relative URI.")
        candidate = package_config_path.parent / Path(*PurePosixPath(decoded).parts)
    elif parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            raise FlutterDependencyIntegrityError(f"{label}.rootUri has a remote file authority.")
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", decoded):
            decoded = decoded[1:]
        candidate = Path(decoded)
        if not candidate.is_absolute():
            raise FlutterDependencyIntegrityError(f"{label}.rootUri file path is not absolute.")
    else:
        raise FlutterDependencyIntegrityError(f"{label}.rootUri scheme is unsupported.")
    return _directory(candidate, f"{label} package root")


def _package_uri(root: Path, value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FlutterDependencyIntegrityError(f"{label}.packageUri is malformed.")
    parsed = urlparse(value)
    decoded = unquote(parsed.path)
    pure = PurePosixPath(decoded)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.params
        or pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
    ):
        raise FlutterDependencyIntegrityError(f"{label}.packageUri may not escape its package.")
    candidate = _directory(root / Path(*pure.parts), f"{label} packageUri")
    if not _within(candidate, root):
        raise FlutterDependencyIntegrityError(f"{label}.packageUri escapes its package root.")
    normalized = pure.as_posix()
    return normalized + ("/" if value.endswith("/") and not normalized.endswith("/") else "")


def _workspace_roots(project_root: Path) -> list[Path]:
    roots = {project_root}
    for candidate in (project_root, *project_root.parents):
        git_marker = candidate / ".git"
        if git_marker.exists():
            _reject_redirected_chain(git_marker, "Workspace Git marker")
            roots.add(candidate.resolve(strict=True))
            break
        pubspec = candidate / "pubspec.yaml"
        if pubspec.is_file():
            try:
                content = pubspec.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise FlutterDependencyIntegrityError(
                    f"Workspace pubspec is unreadable: {error}"
                ) from error
            if _WORKSPACE_MARKER.search(content):
                roots.add(candidate.resolve(strict=True))
                break
    return sorted(roots, key=str)


def _load_package_config(project_root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    config_path = _regular_file(
        project_root / ".dart_tool" / "package_config.json",
        "Dart package_config.json",
    )
    try:
        payload = decode_json_bytes(config_path.read_bytes())
    except (OSError, UnicodeError, ValueError) as error:
        raise FlutterDependencyIntegrityError(
            f"Dart package_config.json is malformed: {error}"
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("configVersion") != 2
        or not isinstance(payload.get("packages"), list)
    ):
        raise FlutterDependencyIntegrityError(
            "Dart package_config.json must use configVersion 2 and a packages array."
        )
    entries: dict[str, dict[str, Any]] = {}
    roots: dict[str, str] = {}
    for index, raw in enumerate(payload["packages"]):
        label = f"package_config.packages[{index}]"
        if (
            not isinstance(raw, dict)
            or not {"name", "rootUri", "packageUri"}.issubset(raw)
            or not set(raw).issubset(_PACKAGE_CONFIG_ENTRY_KEYS)
            or not valid_package_name(raw.get("name"))
        ):
            raise FlutterDependencyIntegrityError(f"{label} has a malformed exact shape.")
        name = raw["name"]
        if name in entries:
            raise FlutterDependencyIntegrityError(
                f"Dart package_config.json contains duplicate package name {name!r}."
            )
        root = _uri_root(raw["rootUri"], config_path, label)
        package_uri = _package_uri(root, raw["packageUri"], label)
        root_key = os.path.normcase(str(root))
        if root_key in roots:
            raise FlutterDependencyIntegrityError(
                f"Packages {roots[root_key]!r} and {name!r} impersonate the same root."
            )
        roots[root_key] = name
        entries[name] = {
            "index": index,
            "root": root,
            "packageUri": package_uri,
        }
    return payload, entries


def prepare_dependency_bundle(
    project_root: Path,
    approved_packages: Mapping[str, Mapping[str, str]],
    required_packages: Mapping[str, Mapping[str, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify the complete product package_config closure against pinned authority."""

    if not isinstance(approved_packages, Mapping) or not isinstance(required_packages, Mapping):
        raise FlutterDependencyIntegrityError(
            "Approved and required package bindings must be exact objects."
        )
    if "flutter" not in required_packages:
        raise FlutterDependencyIntegrityError(
            "The exact required package 'flutter' is absent from profile authority."
        )
    if set(approved_packages) & set(required_packages):
        raise FlutterDependencyIntegrityError(
            "Approved visual packages and required semantic packages must be disjoint."
        )
    payload, entries = _load_package_config(project_root)
    product_name = _pubspec_name(project_root, "Analyzed product")
    product_entry = entries.get(product_name)
    if product_entry is None or product_entry["root"] != project_root:
        raise FlutterDependencyIntegrityError(
            "Dart package_config.json does not bind the analyzed product to its exact root."
        )
    if product_entry["packageUri"] != "lib/":
        raise FlutterDependencyIntegrityError(
            "The analyzed product packageUri must be exactly lib/."
        )
    governed_names = set(approved_packages) | set(required_packages)
    expected_names = governed_names | {product_name}
    if set(entries) != expected_names:
        missing = sorted(expected_names - set(entries))
        unbound = sorted(set(entries) - expected_names)
        raise FlutterDependencyIntegrityError(
            "Dart package_config.json is not the complete profile-bound closure; "
            f"missing={missing!r}, unbound={unbound!r}."
        )
    if product_name in governed_names:
        raise FlutterDependencyIntegrityError(
            "A governed dependency may not impersonate the analyzed product."
        )
    workspace_roots = _workspace_roots(project_root)
    guardian_root = Path(__file__).resolve().parents[1]
    evidence: list[dict[str, Any]] = []
    for package_name in sorted(governed_names):
        authority = (
            "profile_required"
            if package_name in required_packages
            else "catalog_approved"
        )
        entry = entries[package_name]
        if entry["packageUri"] != "lib/":
            raise FlutterDependencyIntegrityError(
                f"Governed package {package_name!r} packageUri must be exactly lib/."
            )
        root = entry["root"]
        if any(_overlaps(root, workspace) for workspace in workspace_roots):
            raise FlutterDependencyIntegrityError(
                f"Governed package {package_name!r} may not use a self/workspace path override."
            )
        if _overlaps(root, guardian_root):
            raise FlutterDependencyIntegrityError(
                f"Governed package {package_name!r} may not impersonate Guardian code."
            )
        if _pubspec_name(root, f"Governed package {package_name!r}") != package_name:
            raise FlutterDependencyIntegrityError(
                f"Governed package {package_name!r} pubspec name does not match package_config."
            )
        files = package_file_manifest(root)
        content_digest = package_content_digest(files)
        bindings = required_packages if authority == "profile_required" else approved_packages
        expected = bindings[package_name]
        if content_digest != expected["contentDigest"]:
            raise FlutterDependencyIntegrityError(
                f"Governed {authority.replace('_', ' ')} package {package_name!r} contentDigest differs from pinned authority."
            )
        evidence.append(
            {
                "name": package_name,
                "authority": authority,
                "canonicalRoot": str(root),
                "rootIdentity": _root_identity(root),
                "packageUri": "lib/",
                "contentDigest": content_digest,
                "repositoryCommit": expected["repositoryCommit"],
                "files": files,
                "fileManifestDigest": sha256_digest(files),
            }
        )
    bundle = {
        "schemaVersion": 1,
        "algorithm": PACKAGE_CONTENT_ALGORITHM,
        "scope": "complete_package_config_closure",
        "packages": evidence,
        "digest": sha256_digest(evidence),
    }
    return payload, bundle


def stage_dependency_bundle(
    stage: Path,
    package_config: dict[str, Any] | None,
    bundle: Mapping[str, Any],
) -> None:
    packages = bundle.get("packages")
    if not packages:
        return
    if package_config is None:
        raise FlutterDependencyIntegrityError(
            "Governed dependencies require a parsed package_config.json."
        )
    staged_config = copy.deepcopy(package_config)
    by_name = {entry["name"]: entry for entry in staged_config["packages"]}
    dependency_root = stage / ".guardian-dependencies"
    dependency_root.mkdir()
    for evidence in packages:
        name = evidence["name"]
        source_root = Path(evidence["canonicalRoot"])
        destination_root = dependency_root / name
        destination_root.mkdir()
        for item in evidence["files"]:
            source = source_root / PurePosixPath(item["path"])
            destination = destination_root / PurePosixPath(item["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if _sha256_file(destination) != item["sha256"]:
                raise FlutterDependencyIntegrityError(
                    f"Governed package {name!r} changed while entering host staging."
                )
        staged_manifest = package_file_manifest(destination_root)
        if staged_manifest != evidence["files"]:
            raise FlutterDependencyIntegrityError(
                f"Governed package {name!r} staging copy is incomplete or changed."
            )
        by_name[name]["rootUri"] = destination_root.resolve().as_uri() + "/"
        by_name[name]["packageUri"] = evidence["packageUri"]
    config_path = stage / ".dart_tool" / "package_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_bytes(canonical_json_bytes(staged_config))


def verify_dependency_bundle(
    project_root: Path,
    bundle: Mapping[str, Any],
) -> dict[str, Any]:
    expected_keys = {"schemaVersion", "algorithm", "scope", "packages", "digest"}
    if (
        not isinstance(bundle, Mapping)
        or set(bundle) != expected_keys
        or bundle.get("schemaVersion") != 1
        or bundle.get("algorithm") != PACKAGE_CONTENT_ALGORITHM
        or bundle.get("scope") != "complete_package_config_closure"
        or not isinstance(bundle.get("packages"), list)
        or bundle.get("digest") != sha256_digest(bundle.get("packages"))
    ):
        raise FlutterDependencyIntegrityError(
            "Sealed governed dependency bundle is malformed or has a mismatched digest."
        )
    workspace_roots = _workspace_roots(project_root)
    guardian_root = Path(__file__).resolve().parents[1]
    names: set[str] = set()
    roots: set[str] = set()
    required_names: set[str] = set()
    for item in bundle["packages"]:
        item_keys = {
            "name",
            "authority",
            "canonicalRoot",
            "rootIdentity",
            "packageUri",
            "contentDigest",
            "repositoryCommit",
            "files",
            "fileManifestDigest",
        }
        if not isinstance(item, dict) or set(item) != item_keys:
            raise FlutterDependencyIntegrityError(
                "Sealed governed dependency evidence has unknown or missing fields."
            )
        name = item.get("name")
        authority = item.get("authority")
        canonical_root = item.get("canonicalRoot")
        if (
            not valid_package_name(name)
            or name in names
            or authority not in {"profile_required", "catalog_approved"}
            or item.get("packageUri") != "lib/"
            or not valid_repository_commit(item.get("repositoryCommit"))
            or not isinstance(canonical_root, str)
            or not Path(canonical_root).is_absolute()
        ):
            raise FlutterDependencyIntegrityError(
                "Sealed governed dependency identity is malformed or duplicated."
            )
        root = _directory(Path(canonical_root), f"Sealed package {name!r}")
        root_key = os.path.normcase(str(root))
        if str(root) != canonical_root or root_key in roots:
            raise FlutterDependencyIntegrityError(
                "Sealed governed dependency root was redirected or replayed."
            )
        if any(_overlaps(root, workspace) for workspace in workspace_roots):
            raise FlutterDependencyIntegrityError(
                f"Sealed package {name!r} now overlaps the analyzed workspace."
            )
        if _overlaps(root, guardian_root):
            raise FlutterDependencyIntegrityError(
                f"Sealed package {name!r} now overlaps Guardian code."
            )
        names.add(name)
        roots.add(root_key)
        if authority == "profile_required":
            required_names.add(name)
        if _pubspec_name(root, f"Sealed package {name!r}") != name:
            raise FlutterDependencyIntegrityError(
                f"Sealed package {name!r} pubspec identity changed."
            )
        files = package_file_manifest(root)
        if (
            _root_identity(root) != item.get("rootIdentity")
            or files != item.get("files")
            or sha256_digest(files) != item.get("fileManifestDigest")
            or package_content_digest(files) != item.get("contentDigest")
        ):
            raise FlutterDependencyIntegrityError(
                f"Sealed governed dependency {name!r} content or manifest changed."
            )
        if _package_uri(root, item.get("packageUri"), f"Sealed package {name!r}") != "lib/":
            raise FlutterDependencyIntegrityError(
                f"Sealed package {name!r} packageUri changed."
            )
    if "flutter" not in required_names:
        raise FlutterDependencyIntegrityError(
            "Sealed dependency evidence lacks the profile-required flutter package."
        )
    return copy.deepcopy(dict(bundle))


__all__ = [
    "FlutterDependencyIntegrityError",
    "package_file_manifest",
    "prepare_dependency_bundle",
    "stage_dependency_bundle",
    "verify_dependency_bundle",
]

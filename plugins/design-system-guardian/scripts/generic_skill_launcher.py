#!/usr/bin/env python3
"""Integrity-bound diagnostic launcher for generic Agent Skills installs."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
BINDING_RELATIVE = Path("references") / "guardian-install.json"
PACKAGE_ENTRIES = (
    ".claude-plugin",
    ".codex-plugin",
    "adapters",
    "assets",
    "benchmarks",
    "docs",
    "guardian_core",
    "policy",
    "schemas",
    "scripts",
    "sentinels",
    "skills",
    "requirements.txt",
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
)
IGNORED_PACKAGE_DIRS = {".dart_tool", ".pytest_cache", "__pycache__", "build"}
IGNORED_PACKAGE_SUFFIXES = {".pyc", ".pyo"}


class LauncherError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, *, missing_exit_code: int = 2) -> dict[str, Any]:
    if not path.is_file():
        raise LauncherError(f"missing JSON evidence: {path}", exit_code=missing_exit_code)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LauncherError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherError(f"invalid JSON evidence: {exc}") from exc
    if not isinstance(payload, dict):
        raise LauncherError("JSON evidence root must be an object")
    return payload


def canonical_json_digest(path: Path) -> str:
    value = load_json(path)
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LauncherError(f"cannot canonicalize {path}: {exc}") from exc
    return hashlib.sha256(payload).hexdigest()


def _package_files(package_root: Path) -> list[Path]:
    files: list[Path] = []
    for entry_name in PACKAGE_ENTRIES:
        entry = package_root / entry_name
        if entry.is_file():
            files.append(entry)
            continue
        if not entry.is_dir():
            raise LauncherError(f"Guardian package entry is missing: {entry_name}")
        for candidate in entry.rglob("*"):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(package_root)
            if any(part in IGNORED_PACKAGE_DIRS for part in relative.parts):
                continue
            if candidate.suffix.lower() in IGNORED_PACKAGE_SUFFIXES:
                continue
            files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(package_root).as_posix())


def package_digest(package_root: Path) -> str:
    digest = hashlib.sha256(b"guardian-package-v1\0")
    for path in _package_files(package_root):
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def managed_files(skill_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(skill_root.rglob("*")):
        if path.is_file() and path.relative_to(skill_root) != BINDING_RELATIVE:
            relative = path.relative_to(skill_root).as_posix()
            result[relative] = sha256_file(path)
    return result


def require_absolute_file(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise LauncherError(f"missing {label} path")
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise LauncherError(f"invalid {label} path: {value}")
    return path.resolve()


def validate_binding(skill_root: Path) -> tuple[Path, Path]:
    binding = load_json(
        skill_root / BINDING_RELATIVE,
        missing_exit_code=4,
    )
    if binding.get("schemaVersion") != 1:
        raise LauncherError("unsupported binding schema")
    if binding.get("mode") != "diagnostic-only":
        raise LauncherError("generic installs may only use diagnostic mode")
    if binding.get("policyDigest") != POLICY_DIGEST:
        raise LauncherError("binding policy digest mismatch")

    package_value = binding.get("packageRoot")
    if not isinstance(package_value, str) or not Path(package_value).is_absolute():
        raise LauncherError("package root must be absolute")
    package_root = Path(package_value).resolve()

    manifest = load_json(package_root / ".codex-plugin" / "plugin.json")
    if manifest.get("version") != binding.get("pluginVersion"):
        raise LauncherError("plugin version binding mismatch")
    if package_digest(package_root) != binding.get("packageDigest"):
        raise LauncherError("Guardian package digest mismatch; reinstall the skills")

    policy_path = package_root / "policy" / "policy-v1.json"
    if canonical_json_digest(policy_path) != POLICY_DIGEST:
        raise LauncherError("immutable policy digest mismatch")

    guardian = binding.get("guardianCli")
    if not isinstance(guardian, dict):
        raise LauncherError("missing Guardian CLI binding")
    guardian_path = require_absolute_file(guardian.get("path"), "Guardian CLI")
    expected_guardian = (package_root / "scripts" / "guardian.py").resolve()
    if guardian_path != expected_guardian:
        raise LauncherError("Guardian CLI is outside the bound package")
    if sha256_file(guardian_path) != guardian.get("sha256"):
        raise LauncherError("Guardian CLI digest mismatch")

    python = binding.get("python")
    if not isinstance(python, dict):
        raise LauncherError("missing Python binding")
    python_path = require_absolute_file(python.get("path"), "Python")
    if sha256_file(python_path) != python.get("sha256"):
        raise LauncherError("Python digest mismatch; reinstall the skills")

    expected_files = binding.get("managedFiles")
    if not isinstance(expected_files, dict) or not expected_files:
        raise LauncherError("missing managed-file evidence")
    if managed_files(skill_root) != expected_files:
        raise LauncherError("managed skill content changed; reinstall the skills")

    return python_path, guardian_path


def main() -> int:
    skill_root = Path(__file__).resolve().parents[1]
    try:
        python_path, guardian_path = validate_binding(skill_root)
    except LauncherError as exc:
        print(f"Design System Guardian blocked: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        print(f"Design System Guardian blocked: filesystem integrity error: {exc}", file=sys.stderr)
        return 2

    try:
        completed = subprocess.run(
            [str(python_path), str(guardian_path), *sys.argv[1:]],
            check=False,
        )
    except OSError as exc:
        print(f"Design System Guardian blocked: cannot execute bound Python: {exc}", file=sys.stderr)
        return 2
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())

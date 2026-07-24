#!/usr/bin/env python3
"""Install Guardian's two skills for generic Agent Skills hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAMES = ("audit-design-system", "build-with-design-system")
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
BINDING_RELATIVE = Path("references") / "guardian-install.json"
LOCK_NAME = ".design-system-guardian-install.lock"
JOURNAL_NAME = ".design-system-guardian-install-journal.json"
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
TRANSACTION_ID = re.compile(r"[0-9a-f]{32}\Z")


class InstallError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InstallError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise InstallError(f"JSON root must be an object: {path}")
    return payload


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InstallError(f"cannot canonicalize JSON: {exc}") from exc


def canonical_json_digest(path: Path) -> str:
    return hashlib.sha256(canonical_json_bytes(load_json(path))).hexdigest()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True).encode("utf-8"))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _package_files(package_root: Path) -> list[Path]:
    files: list[Path] = []
    for entry_name in PACKAGE_ENTRIES:
        entry = package_root / entry_name
        if entry.is_file():
            files.append(entry)
            continue
        if not entry.is_dir():
            raise InstallError(f"Guardian package entry is missing: {entry_name}")
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


def validate_managed_skill(destination: Path) -> dict[str, Any]:
    binding = load_json(destination / BINDING_RELATIVE)
    if binding.get("schemaVersion") != 1 or binding.get("mode") != "diagnostic-only":
        raise InstallError(f"unrecognized managed skill: {destination}")
    if binding.get("policyDigest") != POLICY_DIGEST:
        raise InstallError(f"managed skill policy digest changed: {destination}")
    expected = binding.get("managedFiles")
    if not isinstance(expected, dict) or expected != managed_files(destination):
        raise InstallError(f"refusing to replace modified skill: {destination}")
    return binding


def validate_existing(destination: Path) -> None:
    binding = validate_managed_skill(destination)
    package_value = binding.get("packageRoot")
    if not isinstance(package_value, str) or not package_value:
        raise InstallError(f"managed skill has no package root: {destination}")
    package_path = Path(package_value)
    if not package_path.is_absolute() or package_path.resolve() != PLUGIN_ROOT.resolve():
        raise InstallError(f"skill belongs to another Guardian package: {destination}")


def validate_python(python_path: Path) -> Path:
    if not python_path.is_absolute() or not python_path.is_file():
        raise InstallError("--python must be an existing absolute executable path")
    python_path = python_path.resolve()
    try:
        completed = subprocess.run(
            [
                str(python_path),
                "-I",
                "-c",
                "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)",
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"cannot execute --python: {exc}") from exc
    if completed.returncode != 0:
        raise InstallError("--python must be an executable Python 3.11 or newer")
    return python_path


def make_binding(python_path: Path, plugin_version: str) -> dict[str, Any]:
    guardian_path = (PLUGIN_ROOT / "scripts" / "guardian.py").resolve()
    policy_path = PLUGIN_ROOT / "policy" / "policy-v1.json"
    if canonical_json_digest(policy_path) != POLICY_DIGEST:
        raise InstallError("immutable policy seed digest mismatch")
    return {
        "schemaVersion": 1,
        "mode": "diagnostic-only",
        "packageRoot": str(PLUGIN_ROOT.resolve()),
        "packageDigest": package_digest(PLUGIN_ROOT),
        "pluginVersion": plugin_version,
        "policyDigest": POLICY_DIGEST,
        "guardianCli": {
            "path": str(guardian_path),
            "sha256": sha256_file(guardian_path),
        },
        "python": {
            "path": str(python_path),
            "sha256": sha256_file(python_path),
        },
    }


def stage_skill(
    name: str,
    stage_root: Path,
    binding_base: dict[str, Any],
) -> None:
    source = PLUGIN_ROOT / "skills" / name
    destination = stage_root / name
    shutil.copytree(source, destination)

    launcher_dir = destination / "scripts"
    launcher_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        PLUGIN_ROOT / "scripts" / "generic_skill_launcher.py",
        launcher_dir / "guardian.py",
    )

    binding = dict(binding_base)
    binding["managedFiles"] = managed_files(destination)
    binding_path = destination / BINDING_RELATIVE
    binding_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(binding_path, binding)


def _lock_handle(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_handle(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def install_lock(target_root: Path) -> Iterator[None]:
    lock_path = target_root / LOCK_NAME
    handle = lock_path.open("a+b")
    try:
        try:
            _lock_handle(handle)
        except OSError as exc:
            raise InstallError(f"another Guardian skill install is active: {lock_path}") from exc
        try:
            yield
        finally:
            try:
                _unlock_handle(handle)
            except OSError:
                pass
    finally:
        handle.close()


def write_journal(
    target_root: Path,
    transaction: str,
    had_existing: dict[str, bool],
    *,
    phase: str,
) -> None:
    atomic_write_json(
        target_root / JOURNAL_NAME,
        {
            "schemaVersion": 1,
            "phase": phase,
            "transaction": transaction,
            "targetRoot": str(target_root.resolve()),
            "packageRoot": str(PLUGIN_ROOT.resolve()),
            "skills": had_existing,
        },
    )


def _journal_state(target_root: Path) -> tuple[dict[str, Any], Path, Path]:
    journal_path = target_root / JOURNAL_NAME
    payload = load_json(journal_path)
    if payload.get("schemaVersion") != 1 or payload.get("phase") not in {
        "prepared",
        "committed",
    }:
        raise InstallError(f"invalid install journal: {journal_path}")
    transaction = payload.get("transaction")
    if not isinstance(transaction, str) or not TRANSACTION_ID.fullmatch(transaction):
        raise InstallError(f"invalid install transaction: {journal_path}")
    if payload.get("targetRoot") != str(target_root.resolve()):
        raise InstallError(f"install journal target mismatch: {journal_path}")
    skills = payload.get("skills")
    if not isinstance(skills, dict) or set(skills) != set(SKILL_NAMES):
        raise InstallError(f"install journal skill set mismatch: {journal_path}")
    if any(not isinstance(skills[name], bool) for name in SKILL_NAMES):
        raise InstallError(f"invalid install journal skill state: {journal_path}")
    stage_root, backup_root = _transaction_paths(target_root, transaction)
    return payload, stage_root, backup_root


def _transaction_paths(target_root: Path, transaction: str) -> tuple[Path, Path]:
    """Keep transient skill trees outside the host's watched skill root."""
    parent = target_root.parent
    return (
        parent / f".design-system-guardian-stage-{transaction}",
        parent / f".design-system-guardian-backup-{transaction}",
    )


def _remove_managed_skill(path: Path) -> None:
    validate_managed_skill(path)
    shutil.rmtree(path)


def recover_interrupted(target_root: Path) -> bool:
    journal_path = target_root / JOURNAL_NAME
    if not journal_path.exists():
        return False

    payload, stage_root, backup_root = _journal_state(target_root)
    skills = payload["skills"]
    if payload["phase"] == "committed":
        for name in SKILL_NAMES:
            destination = target_root / name
            if not destination.is_dir():
                raise InstallError(f"committed skill is missing: {destination}")
            validate_managed_skill(destination)
    else:
        for name in SKILL_NAMES:
            destination = target_root / name
            backup = backup_root / name
            had_existing = skills[name]
            if backup.exists():
                if not had_existing:
                    raise InstallError(f"unexpected backup for new skill: {backup}")
                validate_managed_skill(backup)
                if destination.exists():
                    _remove_managed_skill(destination)
                backup.rename(destination)
            elif had_existing:
                if not destination.is_dir():
                    raise InstallError(f"last-good skill is missing: {destination}")
                validate_managed_skill(destination)
            elif destination.exists():
                _remove_managed_skill(destination)

    if stage_root.exists():
        shutil.rmtree(stage_root)
    if backup_root.exists():
        shutil.rmtree(backup_root)
    journal_path.unlink()
    return True


def install(target_root: Path, python_path: Path, replace: bool) -> None:
    python_path = validate_python(python_path)
    target_root = target_root.expanduser().resolve()
    if target_root == Path(target_root.anchor):
        raise InstallError("refusing to use a filesystem root as the skill target")
    target_root.mkdir(parents=True, exist_ok=True)

    with install_lock(target_root):
        recover_interrupted(target_root)

        destinations = [target_root / name for name in SKILL_NAMES]
        for destination in destinations:
            if destination.exists():
                if not replace:
                    raise InstallError(
                        f"destination exists: {destination}; rerun with --replace after review"
                    )
                validate_existing(destination)

        manifest = load_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
        plugin_version = manifest.get("version")
        if not isinstance(plugin_version, str) or not plugin_version:
            raise InstallError("plugin version is missing")
        binding_base = make_binding(python_path, plugin_version)

        transaction = uuid.uuid4().hex
        stage_root, backup_root = _transaction_paths(target_root, transaction)
        had_existing = {
            name: (target_root / name).exists()
            for name in SKILL_NAMES
        }
        stage_root.mkdir()
        backup_root.mkdir()
        write_journal(
            target_root,
            transaction,
            had_existing,
            phase="prepared",
        )

        try:
            for name in SKILL_NAMES:
                stage_skill(name, stage_root, binding_base)

            for name in SKILL_NAMES:
                destination = target_root / name
                backup = backup_root / name
                if destination.exists():
                    destination.rename(backup)
                (stage_root / name).rename(destination)

            for destination in destinations:
                validate_existing(destination)
            write_journal(
                target_root,
                transaction,
                had_existing,
                phase="committed",
            )
        except BaseException as original:
            try:
                recover_interrupted(target_root)
            except BaseException as recovery_error:
                raise InstallError(
                    f"install interrupted and recovery evidence was preserved: {recovery_error}"
                ) from original
            raise

        recover_interrupted(target_root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Install the two Guardian skills without copying Guardian's core.",
    )
    result.add_argument(
        "--target-root",
        required=True,
        type=Path,
        help="Agent skill root such as ~/.agents/skills or .deepcode/skills.",
    )
    result.add_argument(
        "--python",
        required=True,
        type=Path,
        help="Absolute Python 3.11+ executable used for diagnostic Guardian commands.",
    )
    result.add_argument(
        "--replace",
        action="store_true",
        help="Replace only an intact prior install from this exact package.",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        install(arguments.target_root, arguments.python, arguments.replace)
    except (InstallError, OSError) as exc:
        print(f"Design System Guardian install blocked: {exc}", file=sys.stderr)
        return 2
    print(
        "Installed exactly two Guardian skills in diagnostic-only mode at "
        f"{arguments.target_root.expanduser().resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

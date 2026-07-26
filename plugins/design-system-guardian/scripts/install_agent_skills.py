#!/usr/bin/env python3
"""Install Guardian's two skills for generic Agent Skills hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
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
PINNED_REQUIREMENT = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._+!-]*)\Z"
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
RUNTIME_OWNER = "design-system-guardian"
DEFAULT_RUNTIME_BASE = Path.home() / ".design-system-guardian" / "runtimes"
RUNTIME_MARKER_NAME = ".design-system-guardian-runtime.json"
REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
REQUIRED_RUNTIME_PINS = {
    "cffi": "2.1.0",
    "cryptography": "46.0.7",
    "pycparser": "3.0",
}
BOOTSTRAP_DISTRIBUTIONS = ("pip", "setuptools", "wheel")
RUNTIME_IMPORTS = (
    "cffi",
    "cryptography",
    "cryptography.exceptions",
    "cryptography.hazmat.primitives.serialization",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "pycparser",
)
RUNTIME_VERIFICATION = """import importlib
import importlib.metadata
import json
import re
import sys


def normalize_distribution(name):
    return re.sub(r"[-_.]+", "-", name).lower()


pins = json.loads(sys.argv[1])
modules = json.loads(sys.argv[2])
strict = json.loads(sys.argv[3])
bootstrap = {
    normalize_distribution(name)
    for name in json.loads(sys.argv[4])
}
installed = {}
for distribution in importlib.metadata.distributions():
    name = distribution.metadata.get("Name")
    if isinstance(name, str) and name:
        installed[normalize_distribution(name)] = distribution.version

problems = []
for name, expected in pins.items():
    actual = installed.get(normalize_distribution(name))
    if actual != expected:
        problems.append(
            f"{name}: expected {expected}, found {actual if actual is not None else 'missing'}"
        )
if strict:
    unexpected = sorted(set(installed) - set(pins) - bootstrap)
    if unexpected:
        problems.append(
            "unexpected runtime distributions: "
            + ", ".join(f"{name}=={installed[name]}" for name in unexpected)
        )
if problems:
    raise SystemExit("; ".join(problems))
for module in modules:
    importlib.import_module(module)
raise SystemExit(0)
"""


class InstallError(Exception):
    pass


def parse_semver(value: Any, field: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    """Parse strict SemVer 2.0 precedence fields or fail closed."""

    if not isinstance(value, str):
        raise InstallError(f"{field} must be strict SemVer")
    match = SEMVER.fullmatch(value)
    if match is None:
        raise InstallError(f"{field} must be strict SemVer")
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease


def compare_semver(left: str, right: str) -> int:
    """Compare strict SemVer values; build metadata does not affect precedence."""

    left_value = parse_semver(left, "candidate pluginVersion")
    right_value = parse_semver(right, "installed pluginVersion")
    for left_part, right_part in zip(left_value[:3], right_value[:3]):
        if left_part != right_part:
            return 1 if left_part > right_part else -1

    left_pre, right_pre = left_value[3], right_value[3]
    if left_pre is None or right_pre is None:
        if left_pre == right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_identifier, right_identifier in zip(left_pre, right_pre):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_identifier) > int(right_identifier) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_identifier > right_identifier else -1
    if len(left_pre) == len(right_pre):
        return 0
    return 1 if len(left_pre) > len(right_pre) else -1


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


def validate_existing(destination: Path) -> dict[str, Any]:
    binding = validate_managed_skill(destination)
    package_value = binding.get("packageRoot")
    if not isinstance(package_value, str) or not package_value:
        raise InstallError(f"managed skill has no package root: {destination}")
    package_path = Path(package_value)
    if not package_path.is_absolute() or package_path.resolve() != PLUGIN_ROOT.resolve():
        raise InstallError(f"skill belongs to another Guardian package: {destination}")
    return binding


def validate_replacement_versions(
    candidate_version: str,
    existing_bindings: list[tuple[str, dict[str, Any]]],
) -> None:
    """Refuse malformed, divergent, incomplete, or newer managed installs."""

    parse_semver(candidate_version, "candidate pluginVersion")
    if not existing_bindings:
        return
    if len(existing_bindings) != len(SKILL_NAMES):
        raise InstallError("existing Guardian skill set is incomplete")

    versions: list[str] = []
    for skill_name, binding in existing_bindings:
        version = binding.get("pluginVersion")
        parse_semver(version, f"existing {skill_name} pluginVersion")
        versions.append(version)
    if len(set(versions)) != 1:
        raise InstallError("existing Guardian skills have divergent pluginVersion values")
    installed_version = versions[0]
    if compare_semver(candidate_version, installed_version) < 0:
        raise InstallError(
            "refusing to downgrade Guardian-controlled skills from "
            f"{installed_version} to {candidate_version}"
        )


def validate_python(python_path: Path, *, runner: Any | None = None) -> Path:
    if not python_path.is_absolute() or not python_path.is_file():
        raise InstallError("--python must be an existing absolute executable path")
    python_path = python_path.resolve()
    try:
        run = subprocess.run if runner is None else runner
        completed = run(
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


def load_pinned_requirements(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise InstallError(f"cannot read pinned runtime requirements: {exc}") from exc

    pins: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = PINNED_REQUIREMENT.fullmatch(line)
        if match is None:
            raise InstallError(
                "runtime requirements must contain only exact name==version pins; "
                f"invalid line {line_number}"
            )
        distribution, version = match.groups()
        normalized = re.sub(r"[-_.]+", "-", distribution).lower()
        if normalized in pins:
            raise InstallError(f"duplicate pinned runtime requirement: {distribution}")
        pins[normalized] = version
    if not pins:
        raise InstallError("runtime requirements contain no exact pins")
    pins = dict(sorted(pins.items()))
    if pins != REQUIRED_RUNTIME_PINS:
        required = ", ".join(
            f"{name}=={version}"
            for name, version in REQUIRED_RUNTIME_PINS.items()
        )
        raise InstallError(
            "bundled runtime requirements must exactly match the approved pins: "
            f"{required}"
        )
    return pins


def runtime_python_path(runtime_root: Path) -> Path:
    if os.name == "nt":
        return runtime_root / "Scripts" / "python.exe"
    return runtime_root / "bin" / "python"


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_is_redirect(path: Path) -> bool:
    information = os.lstat(path)
    return stat.S_ISLNK(information.st_mode) or bool(
        getattr(information, "st_file_attributes", 0) & REPARSE_POINT_FLAG
    )


def _assert_no_runtime_redirects(path: Path) -> Path:
    absolute = _absolute_without_resolving(path)
    for component in [*reversed(absolute.parents), absolute]:
        try:
            redirected = _path_is_redirect(component)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InstallError(
                f"cannot inspect Guardian runtime storage component {component}: {exc}"
            ) from exc
        if redirected:
            raise InstallError(
                f"Guardian runtime storage redirect is forbidden: {component}"
            )
    return absolute


def _prepare_runtime_base(path: Path, *, enforce_default: bool) -> Path:
    lexical = _assert_no_runtime_redirects(path)
    try:
        lexical.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InstallError(f"cannot create Guardian runtime storage: {exc}") from exc
    lexical = _assert_no_runtime_redirects(lexical)
    if not lexical.is_dir():
        raise InstallError(f"Guardian runtime storage is not a directory: {lexical}")
    try:
        real = lexical.resolve(strict=True)
    except OSError as exc:
        raise InstallError(f"cannot canonicalize Guardian runtime storage: {exc}") from exc

    if enforce_default:
        home = _assert_no_runtime_redirects(Path.home())
        if not home.is_dir():
            raise InstallError(f"Guardian account home is not a directory: {home}")
        try:
            real_home = home.resolve(strict=True)
            expected = (
                real_home / ".design-system-guardian" / "runtimes"
            ).resolve(strict=True)
        except OSError as exc:
            raise InstallError(
                f"cannot canonicalize default Guardian runtime storage: {exc}"
            ) from exc
        if os.path.normcase(str(real)) != os.path.normcase(str(expected)):
            raise InstallError(
                "default Guardian runtime storage escaped "
                "~/.design-system-guardian/runtimes"
            )
    return real


def _runtime_command(
    command: list[str],
    *,
    label: str,
    timeout: int,
    runner: Any | None,
) -> None:
    run = subprocess.run if runner is None else runner
    try:
        completed = run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"{label} failed: {exc}") from exc
    if completed.returncode == 0:
        return
    stderr = completed.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    detail = str(stderr or "").strip().splitlines()
    suffix = f": {detail[-1]}" if detail else ""
    raise InstallError(f"{label} failed with exit {completed.returncode}{suffix}")


def _verify_runtime(
    python_path: Path,
    pins: dict[str, str],
    *,
    strict: bool,
    isolated: bool,
    label: str,
    runner: Any | None,
) -> None:
    command = [str(python_path)]
    if isolated:
        command.append("-I")
    command.extend(
        [
            "-c",
            RUNTIME_VERIFICATION,
            json.dumps(pins, sort_keys=True, separators=(",", ":")),
            json.dumps(RUNTIME_IMPORTS, separators=(",", ":")),
            json.dumps(strict),
            json.dumps(BOOTSTRAP_DISTRIBUTIONS, separators=(",", ":")),
        ]
    )
    _runtime_command(
        command,
        label=label,
        timeout=30,
        runner=runner,
    )


def _verify_host_runtime(
    python_path: Path,
    pins: dict[str, str],
    *,
    runner: Any | None,
) -> None:
    try:
        _verify_runtime(
            python_path,
            pins,
            strict=False,
            isolated=False,
            label="required host runtime verification",
            runner=runner,
        )
    except InstallError as exc:
        raise InstallError(
            f"{exc}; no dependency changes were made. "
            "After explicit permission, rerun with --bootstrap-runtime."
        ) from exc

def provision_runtime(
    target_root: Path,
    source_python: Path,
    *,
    runner: Any | None = None,
    runtime_base: Path | None = None,
) -> Path:
    requirements_path = (PLUGIN_ROOT / "requirements.txt").resolve()
    pins = load_pinned_requirements(requirements_path)
    requirements_digest = sha256_file(requirements_path)
    marker_base: dict[str, Any] = {
        "schemaVersion": 1,
        "owner": RUNTIME_OWNER,
        "targetRoot": str(target_root),
        "requirements": {
            "sha256": requirements_digest,
            "pins": pins,
        },
        "sourcePython": {
            "path": str(source_python),
            "sha256": sha256_file(source_python),
        },
    }
    runtime_id = hashlib.sha256(canonical_json_bytes(marker_base)).hexdigest()[:16]
    selected_runtime_base = _prepare_runtime_base(
        DEFAULT_RUNTIME_BASE if runtime_base is None else runtime_base,
        enforce_default=runtime_base is None,
    )
    runtime_root = selected_runtime_base / runtime_id

    def validate_existing_runtime() -> Path:
        _assert_no_runtime_redirects(runtime_root)
        marker = load_json(runtime_root / RUNTIME_MARKER_NAME)
        python_path = runtime_python_path(runtime_root)
        _assert_no_runtime_redirects(python_path)
        expected = dict(marker_base)
        expected["pythonSha256"] = marker.get("pythonSha256")
        if marker != expected or not isinstance(marker.get("pythonSha256"), str):
            raise InstallError(f"refusing to use unowned or incompatible runtime: {runtime_root}")
        if not python_path.is_file() or sha256_file(python_path) != marker["pythonSha256"]:
            raise InstallError(f"isolated runtime Python integrity mismatch: {runtime_root}")
        _verify_runtime(
            python_path,
            pins,
            strict=True,
            isolated=True,
            label="isolated runtime verification",
            runner=runner,
        )
        return python_path

    if runtime_root.exists():
        if not runtime_root.is_dir():
            raise InstallError(f"isolated runtime path is not a directory: {runtime_root}")
        return validate_existing_runtime()

    stage_root = runtime_root.with_name(f".{runtime_root.name}.{uuid.uuid4().hex}.tmp")
    created_runtime = False
    try:
        _runtime_command(
            [str(source_python), "-I", "-m", "venv", "--copies", str(stage_root)],
            label="isolated runtime creation",
            timeout=120,
            runner=runner,
        )
        _assert_no_runtime_redirects(stage_root)
        stage_python = runtime_python_path(stage_root)
        _assert_no_runtime_redirects(stage_python)
        if not stage_python.is_file():
            raise InstallError("isolated runtime creation did not produce a Python executable")
        _runtime_command(
            [
                str(stage_python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "install",
                "--no-input",
                "--no-deps",
                "--requirement",
                str(requirements_path),
            ],
            label="pinned runtime dependency installation",
            timeout=300,
            runner=runner,
        )
        _verify_runtime(
            stage_python,
            pins,
            strict=True,
            isolated=True,
            label="isolated runtime verification",
            runner=runner,
        )
        marker = dict(marker_base)
        marker["pythonSha256"] = sha256_file(stage_python)
        atomic_write_json(stage_root / RUNTIME_MARKER_NAME, marker)
        stage_root.rename(runtime_root)
        created_runtime = True
        return validate_existing_runtime()
    except BaseException:
        if stage_root.exists():
            shutil.rmtree(stage_root)
        if created_runtime and runtime_root.exists():
            shutil.rmtree(runtime_root)
        raise


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


def install(
    target_root: Path,
    python_path: Path,
    replace: bool,
    *,
    bootstrap_runtime: bool = False,
    runtime_runner: Any | None = None,
    runtime_base: Path | None = None,
) -> None:
    python_path = validate_python(python_path, runner=runtime_runner)
    if not bootstrap_runtime:
        pins = load_pinned_requirements(PLUGIN_ROOT / "requirements.txt")
        _verify_host_runtime(python_path, pins, runner=runtime_runner)

    manifest = load_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
    plugin_version = manifest.get("version")
    parse_semver(plugin_version, "candidate pluginVersion")

    target_root = target_root.expanduser().resolve()
    if target_root == Path(target_root.anchor):
        raise InstallError("refusing to use a filesystem root as the skill target")
    target_root.mkdir(parents=True, exist_ok=True)

    with install_lock(target_root):
        recover_interrupted(target_root)

        destinations = [target_root / name for name in SKILL_NAMES]
        existing_bindings: list[tuple[str, dict[str, Any]]] = []
        for destination in destinations:
            if destination.exists():
                if not replace:
                    raise InstallError(
                        f"destination exists: {destination}; rerun with --replace after review"
                    )
                existing_bindings.append(
                    (destination.name, validate_existing(destination))
                )
        validate_replacement_versions(plugin_version, existing_bindings)

        if bootstrap_runtime:
            python_path = provision_runtime(
                target_root,
                python_path,
                runner=runtime_runner,
                runtime_base=runtime_base,
            )

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
    result.add_argument(
        "--bootstrap-runtime",
        action="store_true",
        help=(
            "With explicit permission, create an isolated Guardian runtime and install "
            "only the bundled pinned requirements before binding the launchers."
        ),
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        install(
            arguments.target_root,
            arguments.python,
            arguments.replace,
            bootstrap_runtime=arguments.bootstrap_runtime,
        )
    except (InstallError, OSError) as exc:
        print(f"Design System Guardian install blocked: {exc}", file=sys.stderr)
        return 2
    runtime_note = " with an isolated Guardian runtime" if arguments.bootstrap_runtime else ""
    print(
        "Installed exactly two Guardian skills in diagnostic-only mode"
        f"{runtime_note} at {arguments.target_root.expanduser().resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

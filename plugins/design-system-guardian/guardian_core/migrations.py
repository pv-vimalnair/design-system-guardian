"""Deterministic append-only, one-version-at-a-time state migrations."""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .canonical import canonical_json_bytes, read_canonical_json, sha256_digest
from .contracts import ExitCode
from .paths import GuardianPaths, PathIntegrityError, assert_guardian_storage_path
from .policy import verify_policy_anchor
from .storage import contained_atomic_write_json, exclusive_write_json, profile_transaction_lock

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PREPARE_KEYS = {
    "schemaVersion", "recordType", "migrationId", "name", "profileId",
    "artifactPath", "fromVersion", "toVersion", "inputDigest",
    "outputDigest", "backupPath", "policyDigest",
}

class MigrationIntegrityError(ValueError):
    exit_code = ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY
class FutureSchemaError(MigrationIntegrityError):
    pass
class MigrationInterruptedError(MigrationIntegrityError):
    pass

@dataclass(frozen=True)
class MigrationStep:
    name: str
    from_version: int
    to_version: int
    transform: Callable[[dict[str, Any]], dict[str, Any]]

@dataclass(frozen=True)
class MigrationRegistry:
    current_version: int
    steps: tuple[MigrationStep, ...]
    def __post_init__(self) -> None:
        if isinstance(self.current_version, bool) or not isinstance(self.current_version, int) or self.current_version < 1:
            raise MigrationIntegrityError("Registry current_version must be a positive integer.")
        by_from: dict[int, MigrationStep] = {}
        for step in self.steps:
            if not isinstance(step, MigrationStep) or not _SAFE_ID.fullmatch(step.name) or isinstance(step.from_version, bool) or not isinstance(step.from_version, int) or step.to_version != step.from_version + 1 or not callable(step.transform):
                raise MigrationIntegrityError("Every migration step must be named and advance exactly one version.")
            if step.from_version in by_from:
                raise MigrationIntegrityError("Migration registry has duplicate source versions.")
            by_from[step.from_version] = step
        if set(by_from) != set(range(1, self.current_version)):
            raise MigrationIntegrityError("Migration registry must contain one contiguous step per version.")
    def step_from(self, version: int) -> MigrationStep:
        return next(step for step in self.steps if step.from_version == version)

@dataclass(frozen=True)
class MigrationResult:
    document: dict[str, Any]
    changed: bool
    applied: tuple[dict[str, Any], ...]
    backup_paths: tuple[Path, ...]

@dataclass(frozen=True)
class RestorationResult:
    document: dict[str, Any]
    record_path: Path
    restoration_id: str

def default_migration_registry() -> MigrationRegistry:
    """Return only migrations compiled into this reviewed Guardian release."""
    return MigrationRegistry(current_version=1, steps=())


def _plain_version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise MigrationIntegrityError("Artifact schemaVersion must be a positive integer.")
    return value

def _artifact(home: Path, profile_id: str, path: Path) -> tuple[Path, str, str]:
    home = home.expanduser().absolute()
    root = GuardianPaths(home).profile(profile_id)
    target = path.expanduser().absolute()
    try:
        assert_guardian_storage_path(home, target)
        relative_profile = target.relative_to(root)
    except (PathIntegrityError, ValueError) as error:
        raise MigrationIntegrityError(f"Migration artifact is outside its profile: {error}") from error
    if not relative_profile.parts or relative_profile.parts[0] == "migrations":
        raise MigrationIntegrityError("Migration targets may not be migration history itself.")
    relative_home = target.relative_to(home).as_posix()
    key = sha256_digest(relative_profile.as_posix().encode("utf-8"))[:24]
    return target, relative_home, key

def _root(home: Path, profile_id: str, key: str) -> Path:
    path = GuardianPaths(home).migrations(profile_id) / key
    return assert_guardian_storage_path(home, path)

def _write_once(home: Path, path: Path, value: dict[str, Any]) -> None:
    try:
        exclusive_write_json(home, path, value)
    except FileExistsError:
        try:
            existing = read_canonical_json(path)
        except (OSError, ValueError, UnicodeError) as error:
            raise MigrationIntegrityError(f"Existing append-only migration evidence is invalid: {error}") from error
        if existing != value:
            raise MigrationIntegrityError("Migration history cannot be replaced or rewritten.")

def _document(path: Path, policy_digest: str) -> dict[str, Any]:
    try:
        value = read_canonical_json(path)
    except (OSError, ValueError, UnicodeError) as error:
        raise MigrationIntegrityError(f"Migration artifact is not canonical JSON: {error}") from error
    if not isinstance(value, dict) or value.get("policyDigest") != policy_digest:
        raise MigrationIntegrityError("Migration artifact is not bound to the immutable policy.")
    _plain_version(value.get("schemaVersion"))
    return value

def _transformed(step: MigrationStep, source: dict[str, Any], policy_digest: str) -> dict[str, Any]:
    try:
        first = step.transform(copy.deepcopy(source))
        second = step.transform(copy.deepcopy(source))
    except Exception as error:
        raise MigrationIntegrityError(f"Migration {step.name} transform failed: {error}") from error
    if not isinstance(first, dict) or canonical_json_bytes(first) != canonical_json_bytes(second):
        raise MigrationIntegrityError(f"Migration {step.name} is not deterministic.")
    if first.get("schemaVersion") != step.to_version:
        raise MigrationIntegrityError(f"Migration {step.name} did not advance exactly one version.")
    if first.get("policyDigest") != policy_digest:
        raise MigrationIntegrityError(f"Migration {step.name} changed the immutable policy digest.")
    return first

def _commit_record(prepare: dict[str, Any]) -> dict[str, Any]:
    return {**copy.deepcopy(prepare), "recordType": "migration_commit", "prepareDigest": sha256_digest(prepare)}

def _verify_backup_reference(
    home: Path,
    *,
    profile_id: str,
    artifact_path: str,
    migration_root: Path,
    backup: Path,
    backup_digest: str,
    policy_digest: str,
) -> None:
    history = migration_root / "history"
    if not history.is_dir():
        raise MigrationIntegrityError("Restoration backup has no migration history.")
    relative_backup = backup.relative_to(home).as_posix()
    matches: list[dict[str, Any]] = []
    for prepare_path in sorted(history.glob("*.prepare.json"), key=lambda item: item.name):
        try:
            prepare = read_canonical_json(prepare_path)
        except (OSError, ValueError, UnicodeError) as error:
            raise MigrationIntegrityError(f"Prepared migration history is invalid: {error}") from error
        if not isinstance(prepare, dict) or set(prepare) != _PREPARE_KEYS:
            raise MigrationIntegrityError("Prepared migration history has an invalid contract.")
        from_version = _plain_version(prepare.get("fromVersion"))
        to_version = _plain_version(prepare.get("toVersion"))
        if (
            prepare.get("schemaVersion") != 1
            or prepare.get("recordType") != "migration_prepare"
            or not isinstance(prepare.get("migrationId"), str)
            or not _HEX_64.fullmatch(prepare["migrationId"])
            or not isinstance(prepare.get("name"), str)
            or not _SAFE_ID.fullmatch(prepare["name"])
            or prepare.get("profileId") != profile_id
            or prepare.get("artifactPath") != artifact_path
            or to_version != from_version + 1
            or not isinstance(prepare.get("inputDigest"), str)
            or not _HEX_64.fullmatch(prepare["inputDigest"])
            or not isinstance(prepare.get("outputDigest"), str)
            or not _HEX_64.fullmatch(prepare["outputDigest"])
            or prepare.get("policyDigest") != policy_digest
        ):
            raise MigrationIntegrityError("Prepared migration history is not bound to this artifact and policy.")
        expected_id = sha256_digest({
            "profileId": profile_id,
            "artifactPath": artifact_path,
            "name": prepare["name"],
            "fromVersion": from_version,
            "toVersion": to_version,
            "inputDigest": prepare["inputDigest"],
            "outputDigest": prepare["outputDigest"],
            "policyDigest": policy_digest,
        })
        expected_backup = (
            migration_root / "backups" / f"v{from_version}-{prepare['inputDigest']}.json"
        ).relative_to(home).as_posix()
        if (
            prepare["migrationId"] != expected_id
            or prepare_path.name != f"{expected_id}.prepare.json"
            or prepare.get("backupPath") != expected_backup
        ):
            raise MigrationIntegrityError("Prepared migration history identity is inconsistent.")
        if prepare["backupPath"] == relative_backup and prepare["inputDigest"] == backup_digest:
            commit_path = history / f"{expected_id}.commit.json"
            try:
                commit = read_canonical_json(commit_path)
            except (OSError, ValueError, UnicodeError) as error:
                raise MigrationIntegrityError("Restoration requires the matching completed migration commit.") from error
            if commit != _commit_record(prepare):
                raise MigrationIntegrityError("Matching migration commit evidence is invalid.")
            matches.append(prepare)
    if len(matches) != 1:
        raise MigrationIntegrityError("Restoration backup must have exactly one completed migration reference.")

def _recover_commit(home: Path, history: Path, current_digest: str) -> None:
    if not history.exists():
        return
    for path in sorted(history.glob("*.prepare.json"), key=lambda item: item.name):
        prepare = read_canonical_json(path)
        if not isinstance(prepare, dict) or prepare.get("recordType") != "migration_prepare":
            raise MigrationIntegrityError("Prepared migration history is malformed.")
        if prepare.get("outputDigest") == current_digest:
            commit = history / path.name.replace(".prepare.json", ".commit.json")
            _write_once(home, commit, _commit_record(prepare))

def _migrate_to_current_locked(home: Path, *, profile_id: str, artifact_path: Path, registry: MigrationRegistry) -> MigrationResult:
    if not isinstance(registry, MigrationRegistry):
        raise MigrationIntegrityError("A validated migration registry is required.")
    policy_digest = verify_policy_anchor(home)
    target, relative, key = _artifact(home, profile_id, artifact_path)
    source = _document(target, policy_digest)
    version = _plain_version(source["schemaVersion"])
    if version > registry.current_version:
        raise FutureSchemaError("Artifact schema is newer than this Guardian runtime.")
    migration_root = _root(home, profile_id, key)
    history = migration_root / "history"
    _recover_commit(home, history, sha256_digest(source))
    if version == registry.current_version:
        return MigrationResult(copy.deepcopy(source), False, (), ())
    applied: list[dict[str, Any]] = []
    backups: list[Path] = []
    while version < registry.current_version:
        step = registry.step_from(version)
        output = _transformed(step, source, policy_digest)
        input_digest, output_digest = sha256_digest(source), sha256_digest(output)
        backup = migration_root / "backups" / f"v{version}-{input_digest}.json"
        _write_once(home, backup, source)
        migration_id = sha256_digest({"profileId": profile_id, "artifactPath": relative, "name": step.name, "fromVersion": version, "toVersion": step.to_version, "inputDigest": input_digest, "outputDigest": output_digest, "policyDigest": policy_digest})
        prepare = {"schemaVersion": 1, "recordType": "migration_prepare", "migrationId": migration_id, "name": step.name, "profileId": profile_id, "artifactPath": relative, "fromVersion": version, "toVersion": step.to_version, "inputDigest": input_digest, "outputDigest": output_digest, "backupPath": backup.relative_to(home).as_posix(), "policyDigest": policy_digest}
        prepare_path = history / f"{migration_id}.prepare.json"
        _write_once(home, prepare_path, prepare)
        try:
            contained_atomic_write_json(home, target, output)
        except Exception as error:
            if verify_policy_anchor(home) != policy_digest:
                raise MigrationIntegrityError("Immutable policy changed during interrupted migration.") from error
            raise MigrationInterruptedError(f"Migration {step.name} replacement was interrupted: {error}") from error
        if _document(target, policy_digest) != output or verify_policy_anchor(home) != policy_digest:
            raise MigrationIntegrityError("Atomic migration replacement failed verification.")
        commit_path = history / f"{migration_id}.commit.json"
        try:
            _write_once(home, commit_path, _commit_record(prepare))
        except Exception as error:
            raise MigrationInterruptedError(f"Migration {step.name} commit record was interrupted: {error}") from error
        applied.append(copy.deepcopy(prepare))
        backups.append(backup)
        source, version = output, step.to_version
    return MigrationResult(copy.deepcopy(source), True, tuple(applied), tuple(backups))

def migrate_to_current(home: Path, *, profile_id: str, artifact_path: Path, registry: MigrationRegistry) -> MigrationResult:
    normalized_home = home.expanduser().absolute()
    with profile_transaction_lock(normalized_home, profile_id):
        return _migrate_to_current_locked(normalized_home, profile_id=profile_id, artifact_path=artifact_path, registry=registry)

def _restoration_time(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MigrationIntegrityError("restored_at must be a timezone-aware datetime.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _restore_backup_locked(home: Path, *, profile_id: str, artifact_path: Path, backup_path: Path, restoration_id: str, reason: str, restored_at: datetime) -> RestorationResult:
    if not isinstance(restoration_id, str) or not _SAFE_ID.fullmatch(restoration_id):
        raise MigrationIntegrityError("restoration_id must be an exact safe identifier.")
    if not isinstance(reason, str) or not reason.strip():
        raise MigrationIntegrityError("Restoration reason must be non-empty.")
    restored_text = _restoration_time(restored_at)
    policy_digest = verify_policy_anchor(home)
    target, relative, key = _artifact(home, profile_id, artifact_path)
    current = _document(target, policy_digest)
    migration_root = _root(home, profile_id, key)
    backup = backup_path.expanduser().absolute()
    try:
        assert_guardian_storage_path(home, backup)
        backup.relative_to(migration_root / "backups")
    except (PathIntegrityError, ValueError) as error:
        raise MigrationIntegrityError("Restoration backup does not belong to this artifact history.") from error
    restored = _document(backup, policy_digest)
    backup_digest = sha256_digest(restored)
    _verify_backup_reference(
        home,
        profile_id=profile_id,
        artifact_path=relative,
        migration_root=migration_root,
        backup=backup,
        backup_digest=backup_digest,
        policy_digest=policy_digest,
    )
    prepare_path = migration_root / "restorations" / f"{restoration_id}.prepare.json"
    record_path = migration_root / "restorations" / f"{restoration_id}.json"
    common = {"schemaVersion": 1, "restorationId": restoration_id, "profileId": profile_id, "artifactPath": relative, "backupPath": backup.relative_to(home).as_posix(), "backupDigest": backup_digest, "restoredDigest": backup_digest, "policyDigest": policy_digest, "reason": reason.strip(), "restoredAt": restored_text}
    if record_path.exists():
        existing = read_canonical_json(record_path)
        expected = {**common, "recordType": "restoration", "previousDigest": existing.get("previousDigest"), "prepareDigest": existing.get("prepareDigest")}
        if existing != expected or sha256_digest(_document(target, policy_digest)) != backup_digest:
            raise MigrationIntegrityError("Existing restoration record conflicts with current evidence.")
        return RestorationResult(copy.deepcopy(restored), record_path, restoration_id)
    if prepare_path.exists():
        prepare = read_canonical_json(prepare_path)
        expected_common = {key: value for key, value in prepare.items() if key not in {"recordType", "previousDigest"}}
        if expected_common != common or prepare.get("recordType") != "restoration_prepare":
            raise MigrationIntegrityError("Prepared restoration conflicts with requested evidence.")
        current_digest = sha256_digest(current)
        if current_digest not in {prepare.get("previousDigest"), backup_digest}:
            raise MigrationIntegrityError("Artifact changed after restoration preparation.")
    else:
        prepare = {**common, "recordType": "restoration_prepare", "previousDigest": sha256_digest(current)}
        _write_once(home, prepare_path, prepare)
    if sha256_digest(current) != backup_digest:
        try:
            contained_atomic_write_json(home, target, restored)
        except Exception as error:
            raise MigrationInterruptedError(f"Restoration replacement was interrupted: {error}") from error
    if _document(target, policy_digest) != restored or verify_policy_anchor(home) != policy_digest:
        raise MigrationIntegrityError("Restored artifact or immutable policy failed verification.")
    record = {**prepare, "recordType": "restoration", "prepareDigest": sha256_digest(prepare)}
    try:
        _write_once(home, record_path, record)
    except Exception as error:
        raise MigrationInterruptedError(f"Restoration record was interrupted: {error}") from error
    return RestorationResult(copy.deepcopy(restored), record_path, restoration_id)

def restore_backup(home: Path, *, profile_id: str, artifact_path: Path, backup_path: Path, restoration_id: str, reason: str, restored_at: datetime) -> RestorationResult:
    normalized_home = home.expanduser().absolute()
    with profile_transaction_lock(normalized_home, profile_id):
        return _restore_backup_locked(normalized_home, profile_id=profile_id, artifact_path=artifact_path, backup_path=backup_path, restoration_id=restoration_id, reason=reason, restored_at=restored_at)

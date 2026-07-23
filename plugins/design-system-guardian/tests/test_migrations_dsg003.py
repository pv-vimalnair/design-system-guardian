import copy
import threading
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import DEFAULT_TEST_CATALOG_AUTHORITY

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)

def provision(home: Path) -> tuple[Path, str]:
    from guardian_core.canonical import atomic_write_json
    from guardian_core.policy import install_policy_anchor
    key = home / "catalog-authority-input.pem"
    key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    digest = install_policy_anchor(home, catalog_authority_public_key=key).digest
    artifact = home / "profiles" / "example-company" / "runtime-state.json"
    atomic_write_json(artifact, {"schemaVersion": 1, "policyDigest": digest, "value": "original"})
    return artifact, digest

def registry():
    from guardian_core.migrations import MigrationRegistry, MigrationStep
    def one_to_two(document: dict) -> dict:
        return {**document, "schemaVersion": 2, "auditStatus": "not_assessed"}
    def two_to_three(document: dict) -> dict:
        return {**document, "schemaVersion": 3, "coverageRequired": True}
    return MigrationRegistry(current_version=3, steps=(
        MigrationStep(name="add-audit-status", from_version=1, to_version=2, transform=one_to_two),
        MigrationStep(name="require-coverage", from_version=2, to_version=3, transform=two_to_three),
    ))

class MigrationTest(unittest.TestCase):
    def test_concurrent_divergent_registries_cannot_last_write_win(self) -> None:
        from guardian_core.canonical import read_canonical_json, sha256_digest
        from guardian_core.migrations import MigrationRegistry, MigrationStep, migrate_to_current
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, _ = provision(home)
            barrier = threading.Barrier(2)
            def run(label: str):
                step = MigrationStep(name=f"branch-{label}", from_version=1, to_version=2, transform=lambda doc: {**doc, "schemaVersion": 2, "branch": label})
                registry = MigrationRegistry(current_version=2, steps=(step,))
                barrier.wait()
                return migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(run, ("a", "b")))
            final = read_canonical_json(artifact)
            self.assertIn(final["branch"], {"a", "b"})
            prepares = list((home / "profiles" / "example-company" / "migrations").rglob("*.prepare.json"))
            commits = list((home / "profiles" / "example-company" / "migrations").rglob("*.commit.json"))
            self.assertEqual(len(prepares), 1)
            self.assertEqual(len(commits), 1)
            self.assertEqual(read_canonical_json(prepares[0])["outputDigest"], sha256_digest(final))
            self.assertEqual(sum(result.changed for result in results), 1)

    def test_migrations_are_one_version_at_a_time_backed_up_and_idempotent(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.migrations import migrate_to_current
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, digest = provision(home)
            first = migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            history_before = {path.relative_to(home).as_posix(): path.read_bytes() for path in (home / "profiles" / "example-company" / "migrations").rglob("*.json")}
            second = migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            history_after = {path.relative_to(home).as_posix(): path.read_bytes() for path in (home / "profiles" / "example-company" / "migrations").rglob("*.json")}
            self.assertTrue(first.changed)
            self.assertEqual([(item["fromVersion"], item["toVersion"]) for item in first.applied], [(1, 2), (2, 3)])
            self.assertEqual(read_canonical_json(artifact)["schemaVersion"], 3)
            self.assertEqual(read_canonical_json(artifact)["policyDigest"], digest)
            self.assertEqual(read_canonical_json(first.backup_paths[0])["schemaVersion"], 1)
            self.assertFalse(second.changed)
            self.assertEqual(history_before, history_after)

    def test_interrupted_replacement_recovers_without_rewriting_prepare_history(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.migrations import MigrationInterruptedError, migrate_to_current
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, _ = provision(home)
            with patch("guardian_core.migrations.contained_atomic_write_json", side_effect=OSError("interrupted")):
                with self.assertRaises(MigrationInterruptedError):
                    migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            self.assertEqual(read_canonical_json(artifact)["schemaVersion"], 1)
            prepares = list((home / "profiles" / "example-company" / "migrations").rglob("*.prepare.json"))
            self.assertEqual(len(prepares), 1)
            prepare_bytes = prepares[0].read_bytes()
            recovered = migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            self.assertEqual(read_canonical_json(artifact)["schemaVersion"], 3)
            self.assertEqual(prepares[0].read_bytes(), prepare_bytes)
            self.assertTrue(recovered.changed)

    def test_future_schema_and_policy_digest_mutation_fail_closed(self) -> None:
        from guardian_core.canonical import atomic_write_json, read_canonical_json
        from guardian_core.migrations import FutureSchemaError, MigrationIntegrityError, MigrationRegistry, MigrationStep, migrate_to_current
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, digest = provision(home)
            atomic_write_json(artifact, {"schemaVersion": 9, "policyDigest": digest})
            before = artifact.read_bytes()
            with self.assertRaises(FutureSchemaError):
                migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            self.assertEqual(artifact.read_bytes(), before)
            atomic_write_json(artifact, {"schemaVersion": 1, "policyDigest": digest})
            malicious = MigrationRegistry(current_version=2, steps=(MigrationStep(name="weaken", from_version=1, to_version=2, transform=lambda doc: {**doc, "schemaVersion": 2, "policyDigest": "0" * 64}),))
            before = artifact.read_bytes()
            with self.assertRaises(MigrationIntegrityError):
                migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=malicious)
            self.assertEqual(artifact.read_bytes(), before)
            self.assertEqual(read_canonical_json(artifact)["policyDigest"], digest)

    def test_restore_is_new_append_only_history_and_never_deletes_migrations(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.migrations import migrate_to_current, restore_backup
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, _ = provision(home)
            migrated = migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            history_root = home / "profiles" / "example-company" / "migrations"
            prior = {path.relative_to(home).as_posix(): path.read_bytes() for path in history_root.rglob("*.json")}
            restored = restore_backup(home, profile_id="example-company", artifact_path=artifact, backup_path=migrated.backup_paths[0], restoration_id="restore-release-7", reason="Logged rollback", restored_at=NOW)
            repeated = restore_backup(home, profile_id="example-company", artifact_path=artifact, backup_path=migrated.backup_paths[0], restoration_id="restore-release-7", reason="Logged rollback", restored_at=NOW)
            self.assertEqual(restored, repeated)
            self.assertEqual(read_canonical_json(artifact)["schemaVersion"], 1)
            after = {path.relative_to(home).as_posix(): path.read_bytes() for path in history_root.rglob("*.json")}
            for path, payload in prior.items():
                self.assertEqual(after[path], payload)
            self.assertEqual(read_canonical_json(restored.record_path)["recordType"], "restoration")

    def test_restore_rejects_caller_created_backup_without_migration_reference(self) -> None:
        from guardian_core.canonical import atomic_write_json, read_canonical_json, sha256_digest
        from guardian_core.migrations import MigrationIntegrityError, migrate_to_current, restore_backup
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, policy_digest = provision(home)
            migrated = migrate_to_current(home, profile_id="example-company", artifact_path=artifact, registry=registry())
            forged = {"schemaVersion": 1, "policyDigest": policy_digest, "value": "caller-forged"}
            forged_path = migrated.backup_paths[0].parent / f"v1-{sha256_digest(forged)}.json"
            atomic_write_json(forged_path, forged)
            with self.assertRaises(MigrationIntegrityError):
                restore_backup(home, profile_id="example-company", artifact_path=artifact, backup_path=forged_path, restoration_id="forged-restore", reason="Attempted forged backup", restored_at=NOW)
            self.assertEqual(read_canonical_json(artifact)["schemaVersion"], 3)
            self.assertNotEqual(read_canonical_json(artifact).get("value"), "caller-forged")

if __name__ == "__main__":
    unittest.main()

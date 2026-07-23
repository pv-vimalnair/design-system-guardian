from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor, verify_policy_anchor
from tests.catalog_authority_test_support import DEFAULT_TEST_CATALOG_AUTHORITY
from tests.release_authority_test_support import (
    DEFAULT_TEST_RELEASE_AUTHORITY,
    new_test_release_authority,
    release_public_key_path,
    sign_release_manifest,
)


NOW = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)
ISSUED_AT = "2026-07-15T09:00:00Z"
COMMIT_A = "1" * 40
COMMIT_B = "2" * 64


def _write(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _unsigned_manifest(
    *,
    version: str,
    channel: str,
    sequence: int,
    artifact_digest: str,
    source_commit: str,
    manifest_type: str = "release",
    target_manifest_digest: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "manifestType": manifest_type,
        "pluginName": "design-system-guardian",
        "pluginVersion": version,
        "channel": channel,
        "channelSequence": sequence,
        "sourceCommit": source_commit,
        "artifactDigest": artifact_digest,
        "policyDigest": EXPECTED_POLICY_SHA256,
        "stateSchemaVersion": 1,
        "runtimeCompatibility": {
            "minimumVersion": "0.1.0",
            "maximumVersionExclusive": "1.0.0",
        },
        "issuedAt": ISSUED_AT,
        "targetManifestDigest": target_manifest_digest,
        "reason": reason,
    }


def _provision(home: Path) -> None:
    catalog_key = home / "catalog-authority.pem"
    catalog_key.parent.mkdir(parents=True, exist_ok=True)
    catalog_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    install_policy_anchor(home, catalog_authority_public_key=catalog_key)
    from guardian_core.release import _enroll_release_authority_at_home

    _enroll_release_authority_at_home(home, release_public_key_path(home))


class ReleaseLifecycleTest(unittest.TestCase):
    def test_unsigned_wrong_key_and_changed_signature_are_rejected(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _verify_release_manifest_at_home as verify_release_manifest,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            unsigned = _unsigned_manifest(
                version="0.1.0",
                channel="canary",
                sequence=1,
                artifact_digest=digest,
                source_commit=COMMIT_A,
            )
            with self.assertRaises(ReleaseIntegrityError):
                verify_release_manifest(home, unsigned)

            wrong = sign_release_manifest(unsigned, new_test_release_authority())
            with self.assertRaises(ReleaseIntegrityError):
                verify_release_manifest(home, wrong)

            changed = sign_release_manifest(unsigned)
            changed["artifactDigest"] = "f" * 64
            with self.assertRaises(ReleaseIntegrityError):
                verify_release_manifest(home, changed)

    def test_canary_then_matching_stable_release_is_archived_and_promoted(self) -> None:
        from guardian_core.canonical import read_canonical_json, sha256_digest
        from guardian_core.release import (
            _promote_release_at_home as promote_release,
            _read_channel_state_at_home as read_channel_state,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            canary = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=1,
                    artifact_digest=digest,
                    source_commit=COMMIT_A,
                )
            )
            stable = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="stable",
                    sequence=1,
                    artifact_digest=digest,
                    source_commit=COMMIT_A,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                canary_result = promote_release(home, canary, artifact)
                stable_result = promote_release(home, stable, artifact)

            self.assertEqual(read_channel_state(home, "canary")["pluginVersion"], "0.1.0")
            self.assertEqual(read_channel_state(home, "stable")["pluginVersion"], "0.1.0")
            self.assertEqual(stable_result.record_type, "promotion")
            release_root = home / "releases"
            self.assertEqual(
                read_canonical_json(release_root / "manifests" / f"{sha256_digest(canary)}.json"),
                canary,
            )
            self.assertTrue((release_root / "artifacts" / f"{digest}.plugin").is_file())
            self.assertTrue(canary_result.history_path.is_file())
            self.assertTrue(stable_result.history_path.is_file())

    def test_stable_without_matching_canary_is_rejected(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _promote_release_at_home as promote_release,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            stable = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="stable",
                    sequence=1,
                    artifact_digest=digest,
                    source_commit=COMMIT_A,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                with self.assertRaises(ReleaseIntegrityError):
                    promote_release(home, stable, artifact)

    def test_normal_downgrade_is_rejected_but_signed_restoration_is_logged(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.release import (
            ReleaseIntegrityError,
            _promote_release_at_home as promote_release,
            _read_channel_state_at_home as read_channel_state,
            _read_release_history_at_home as read_release_history,
            _rollback_release_at_home as rollback_release,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            first_artifact = home / "first.plugin"
            second_artifact = home / "second.plugin"
            first_digest = _write(first_artifact, b"release-1")
            second_digest = _write(second_artifact, b"release-2")
            first = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=1,
                    artifact_digest=first_digest,
                    source_commit=COMMIT_A,
                )
            )
            second = sign_release_manifest(
                _unsigned_manifest(
                    version="0.2.0",
                    channel="canary",
                    sequence=2,
                    artifact_digest=second_digest,
                    source_commit=COMMIT_B,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                promote_release(home, first, first_artifact)
                promote_release(home, second, second_artifact)

                downgrade = sign_release_manifest(
                    _unsigned_manifest(
                        version="0.1.0",
                        channel="canary",
                        sequence=3,
                        artifact_digest=first_digest,
                        source_commit=COMMIT_A,
                    )
                )
                with self.assertRaises(ReleaseIntegrityError):
                    promote_release(home, downgrade, first_artifact)

                restoration = sign_release_manifest(
                    _unsigned_manifest(
                        version="0.1.0",
                        channel="canary",
                        sequence=3,
                        artifact_digest=first_digest,
                        source_commit=COMMIT_A,
                        manifest_type="restoration",
                        target_manifest_digest=sha256_digest(first),
                        reason="Restore the last reviewed canary.",
                    )
                )
                result = rollback_release(home, restoration)
                disguised_downgrade = sign_release_manifest(
                    _unsigned_manifest(
                        version="0.1.1",
                        channel="canary",
                        sequence=4,
                        artifact_digest=first_digest,
                        source_commit=COMMIT_A,
                    )
                )
                with self.assertRaises(ReleaseIntegrityError):
                    promote_release(home, disguised_downgrade, first_artifact)

            state = read_channel_state(home, "canary")
            self.assertEqual(state["pluginVersion"], "0.1.0")
            self.assertEqual(state["activeManifestDigest"], sha256_digest(first))
            self.assertEqual(state["actionManifestDigest"], sha256_digest(restoration))
            self.assertEqual(result.record_type, "restoration")
            history = read_release_history(home, "canary")
            self.assertEqual([entry["recordType"] for entry in history], ["promotion", "promotion", "restoration"])
            self.assertEqual(verify_policy_anchor(home), EXPECTED_POLICY_SHA256)

    def test_interrupted_channel_state_write_recovers_without_duplicate_history(self) -> None:
        import guardian_core.release as release_module
        from guardian_core.release import (
            _promote_release_at_home as promote_release,
            _read_channel_state_at_home as read_channel_state,
            _read_release_history_at_home as read_release_history,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            manifest = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=1,
                    artifact_digest=digest,
                    source_commit=COMMIT_A,
                )
            )
            original_write = release_module.contained_atomic_write_json
            calls = 0

            def interrupt_once(home_path: Path, path: Path, value: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("simulated channel-state interruption")
                original_write(home_path, path, value)

            with patch("guardian_core.release._utc_now", return_value=NOW):
                with patch("guardian_core.release.contained_atomic_write_json", side_effect=interrupt_once):
                    with self.assertRaises(OSError):
                        promote_release(home, manifest, artifact)
                result = promote_release(home, manifest, artifact)

            self.assertEqual(result.record_type, "promotion")
            self.assertEqual(read_channel_state(home, "canary")["pluginVersion"], "0.1.0")
            history = read_release_history(home, "canary")
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["recordedAt"], "2026-07-15T10:00:00Z")

    def test_replayed_older_channel_state_is_detected_against_history(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _promote_release_at_home as promote_release,
            _read_release_history_at_home as read_release_history,
            _read_channel_state_at_home as read_channel_state,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            first_artifact = home / "first.plugin"
            second_artifact = home / "second.plugin"
            first_digest = _write(first_artifact, b"release-1")
            second_digest = _write(second_artifact, b"release-2")
            first = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=1,
                    artifact_digest=first_digest,
                    source_commit=COMMIT_A,
                )
            )
            second = sign_release_manifest(
                _unsigned_manifest(
                    version="0.2.0",
                    channel="canary",
                    sequence=2,
                    artifact_digest=second_digest,
                    source_commit=COMMIT_B,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                first_result = promote_release(home, first, first_artifact)
                old_state = first_result.state_path.read_bytes()
                promote_release(home, second, second_artifact)
            first_result.state_path.write_bytes(old_state)
            with self.assertRaises(ReleaseIntegrityError):
                read_channel_state(home, "canary")

            history_root = home / "releases" / "history" / "canary"
            history_files = sorted(history_root.glob("*.json"), key=lambda path: path.name)
            self.assertEqual(len(history_files), 2)
            history_files[-1].unlink()
            with self.assertRaises(ReleaseIntegrityError):
                read_channel_state(home, "canary")
            with self.assertRaises(ReleaseIntegrityError):
                read_release_history(home, "canary")
    def test_future_schema_wrong_policy_short_commit_and_artifact_mismatch_fail(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _promote_release_at_home as promote_release,
            _verify_release_manifest_at_home as verify_release_manifest,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            base = _unsigned_manifest(
                version="0.1.0",
                channel="canary",
                sequence=1,
                artifact_digest=digest,
                source_commit=COMMIT_A,
            )
            for field, value in (
                ("schemaVersion", 2),
                ("stateSchemaVersion", 2),
                ("policyDigest", "f" * 64),
                ("sourceCommit", "1" * 12),
            ):
                changed = sign_release_manifest(base)
                changed[field] = value
                with self.assertRaises(ReleaseIntegrityError, msg=field):
                    verify_release_manifest(home, changed)

            signed = sign_release_manifest(base)
            artifact.write_bytes(b"changed-after-signing")
            with patch("guardian_core.release._utc_now", return_value=NOW):
                with self.assertRaises(ReleaseIntegrityError):
                    promote_release(home, signed, artifact)

    def test_release_authority_is_create_once_and_production_has_no_signer(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _enroll_release_authority_at_home as enroll_release_authority,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            replacement = new_test_release_authority()
            with self.assertRaises(ReleaseIntegrityError):
                enroll_release_authority(home, release_public_key_path(home, replacement))

        production = "\n".join(
            path.read_text("utf-8")
            for path in (Path(__file__).parents[1] / "guardian_core").glob("*.py")
        )
        self.assertNotIn("Ed25519PrivateKey", production)
        self.assertNotIn(".sign(", production)
        self.assertNotIn("generate()", production)


class ReleasePackagingContractTest(unittest.TestCase):
    def test_plugin_exposes_exactly_two_visible_skills_and_valid_semver_metadata(self) -> None:
        from guardian_core.release import RUNTIME_VERSION

        root = Path(__file__).parents[1]
        skill_dirs = sorted(path.name for path in (root / "skills").iterdir() if path.is_dir())
        self.assertEqual(skill_dirs, ["audit-design-system", "build-with-design-system"])
        manifest = json.loads((root / ".codex-plugin" / "plugin.json").read_text("utf-8"))
        self.assertEqual(manifest["name"], "design-system-guardian")
        self.assertEqual(manifest["skills"], "./skills/")
        self.assertEqual(manifest["version"], RUNTIME_VERSION)
        self.assertEqual(len(manifest["interface"]["defaultPrompt"]), 2)
        self.assertEqual(set(manifest["interface"]["capabilities"]), {"Read", "Write"})
        self.assertNotIn("hooks", manifest)
        self.assertNotIn("mcpServers", manifest)
        self.assertNotIn("apps", manifest)


if __name__ == "__main__":
    unittest.main()

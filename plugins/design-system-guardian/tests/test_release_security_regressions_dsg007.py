from __future__ import annotations

import copy
import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from guardian_core.canonical import sha256_digest
from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor
from tests.catalog_authority_test_support import DEFAULT_TEST_CATALOG_AUTHORITY
from tests.release_authority_test_support import (
    release_public_key_path,
    sign_release_manifest,
)
from tests.test_release_dsg007 import (
    COMMIT_A,
    COMMIT_B,
    NOW,
    _provision,
    _unsigned_manifest,
    _write,
)


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LATER = datetime(2026, 7, 15, 11, 0, tzinfo=timezone.utc)
BETWEEN = datetime(2026, 7, 15, 10, 30, tzinfo=timezone.utc)


class ReleaseSecurityRegressionTest(unittest.TestCase):
    def test_public_channel_surface_has_no_home_override_and_blocks_without_worm_provider(self) -> None:
        from guardian_core import release
        from guardian_core.release_head_provider import ExternalReleaseHeadUnavailable

        expected = {
            "read_channel_state": ("channel",),
            "read_release_history": ("channel",),
            "promote_release": ("manifest", "artifact_path"),
            "rollback_release": ("restoration_manifest",),
        }
        for name, parameters in expected.items():
            self.assertEqual(tuple(inspect.signature(getattr(release, name)).parameters), parameters)

        with self.assertRaises(ExternalReleaseHeadUnavailable):
            release.read_channel_state("canary")
        with self.assertRaises(ExternalReleaseHeadUnavailable):
            release.read_release_history("stable")
        with self.assertRaises(ExternalReleaseHeadUnavailable):
            release.promote_release({}, Path("not-read.plugin"))
        with self.assertRaises(ExternalReleaseHeadUnavailable):
            release.rollback_release({})

        provider_source = (PLUGIN_ROOT / "guardian_core" / "release_head_provider.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("os.environ", provider_source)
        self.assertNotIn("TemporaryDirectory", provider_source)
        self.assertIn("compare_and_swap", provider_source)

    def test_archived_v1_remains_readable_but_cannot_activate_after_schema_advance(self) -> None:
        import guardian_core.release as release

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            first = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=1,
                    artifact_digest=digest,
                    source_commit=COMMIT_A,
                )
            )
            candidate = sign_release_manifest(
                _unsigned_manifest(
                    version="0.2.0",
                    channel="canary",
                    sequence=2,
                    artifact_digest=digest,
                    source_commit=COMMIT_B,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                release._promote_release_at_home(home, first, artifact)

            with patch.multiple(
                release,
                RUNTIME_VERSION="2.0.0",
                CURRENT_RELEASE_SCHEMA_VERSION=2,
                SUPPORTED_RELEASE_SCHEMA_VERSIONS=frozenset({1, 2}),
                CURRENT_STATE_SCHEMA_VERSION=2,
                SUPPORTED_STATE_SCHEMA_VERSIONS=frozenset({1, 2}),
            ):
                self.assertEqual(
                    release._read_channel_state_at_home(home, "canary")["pluginVersion"],
                    "0.1.0",
                )
                self.assertEqual(len(release._read_release_history_at_home(home, "canary")), 1)
                with self.assertRaises(release.ReleaseIntegrityError):
                    release._verify_release_manifest_at_home(home, candidate)

    def test_stable_state_is_bound_to_exact_canary_event_and_fails_when_proof_is_lost(self) -> None:
        from guardian_core.release import (
            ReleaseIntegrityError,
            _promote_release_at_home,
            _read_channel_state_at_home,
            _read_release_history_at_home,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            artifact = home / "artifact.plugin"
            digest = _write(artifact, b"release-a")
            canary = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0", channel="canary", sequence=1,
                    artifact_digest=digest, source_commit=COMMIT_A,
                )
            )
            stable = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0", channel="stable", sequence=1,
                    artifact_digest=digest, source_commit=COMMIT_A,
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                _promote_release_at_home(home, canary, artifact)
                _promote_release_at_home(home, stable, artifact)

            canary_event = _read_release_history_at_home(home, "canary")[0]
            stable_state = _read_channel_state_at_home(home, "stable")
            self.assertEqual(stable_state["canaryEvidenceDigest"], sha256_digest(canary_event))

            next((home / "releases" / "history" / "canary").glob("*.json")).unlink()
            with self.assertRaises(ReleaseIntegrityError):
                _read_channel_state_at_home(home, "stable")

    def test_release_and_catalog_authorities_must_be_distinct(self) -> None:
        from guardian_core.release import ReleaseIntegrityError, _enroll_release_authority_at_home

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            catalog_key = home / "catalog.pem"
            catalog_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
            install_policy_anchor(home, catalog_authority_public_key=catalog_key)
            same_key = home / "release.pem"
            same_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
            with self.assertRaises(ReleaseIntegrityError):
                _enroll_release_authority_at_home(home, same_key)

    def test_recording_and_activation_times_are_monotonic(self) -> None:
        from guardian_core.release import ReleaseIntegrityError, _promote_release_at_home

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            first_artifact = home / "first.plugin"
            second_artifact = home / "second.plugin"
            first_digest = _write(first_artifact, b"release-1")
            second_digest = _write(second_artifact, b"release-2")
            first = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0", channel="canary", sequence=1,
                    artifact_digest=first_digest, source_commit=COMMIT_A,
                )
            )
            second = sign_release_manifest(
                _unsigned_manifest(
                    version="0.2.0", channel="canary", sequence=2,
                    artifact_digest=second_digest, source_commit=COMMIT_B,
                )
            )
            calls = 0

            def delayed_activation_clock() -> datetime:
                nonlocal calls
                calls += 1
                return NOW if calls <= 2 else LATER

            with patch("guardian_core.release._utc_now", side_effect=delayed_activation_clock):
                _promote_release_at_home(home, first, first_artifact)
            with patch("guardian_core.release._utc_now", return_value=BETWEEN):
                with self.assertRaisesRegex(
                    ReleaseIntegrityError, "timestamps cannot be later than the trusted host clock"
                ):
                    _promote_release_at_home(home, second, second_artifact)

    def test_interrupted_restoration_state_write_recovers_without_duplicate_history(self) -> None:
        import guardian_core.release as release

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
            restoration = sign_release_manifest(
                _unsigned_manifest(
                    version="0.1.0",
                    channel="canary",
                    sequence=3,
                    artifact_digest=first_digest,
                    source_commit=COMMIT_A,
                    manifest_type="restoration",
                    target_manifest_digest=sha256_digest(first),
                    reason="Restore reviewed canary after incident.",
                )
            )
            with patch("guardian_core.release._utc_now", return_value=NOW):
                release._promote_release_at_home(home, first, first_artifact)
                release._promote_release_at_home(home, second, second_artifact)

            original_write = release.contained_atomic_write_json
            calls = 0

            def interrupt_once(home_path: Path, path: Path, value: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("simulated restoration state interruption")
                original_write(home_path, path, value)

            with patch("guardian_core.release._utc_now", return_value=NOW):
                with patch(
                    "guardian_core.release.contained_atomic_write_json",
                    side_effect=interrupt_once,
                ):
                    with self.assertRaises(OSError):
                        release._rollback_release_at_home(home, restoration)
                    result = release._rollback_release_at_home(home, restoration)

            self.assertEqual(result.record_type, "restoration")
            state = release._read_channel_state_at_home(home, "canary")
            self.assertEqual(state["activeManifestDigest"], sha256_digest(first))
            self.assertEqual(state["actionManifestDigest"], sha256_digest(restoration))
            history = release._read_release_history_at_home(home, "canary")
            self.assertEqual(
                [entry["recordType"] for entry in history],
                ["promotion", "promotion", "restoration"],
            )


class ReleaseSchemaRuntimeParityTest(unittest.TestCase):
    @staticmethod
    def _schema(name: str) -> dict[str, object]:
        return json.loads((PLUGIN_ROOT / "schemas" / "release" / name).read_text("utf-8"))

    def test_manifest_schema_and_runtime_reject_stable_prerelease_and_noncanonical_reason(self) -> None:
        from guardian_core.release import ReleaseIntegrityError, _validate_manifest_contract

        digest = "a" * 64
        base = _unsigned_manifest(
            version="0.1.0-beta.1", channel="canary", sequence=1,
            artifact_digest=digest, source_commit=COMMIT_A,
        )
        base["authority"] = {
            "schemaVersion": 1,
            "algorithm": "ed25519",
            "keyId": "b" * 64,
            "signature": "A" * 86 + "==",
        }
        validator = Draft202012Validator(self._schema("release-manifest.schema.json"))
        self.assertFalse(list(validator.iter_errors(base)))
        _validate_manifest_contract(base)

        boolean_schema = copy.deepcopy(base)
        boolean_schema["authority"]["schemaVersion"] = True
        self.assertTrue(list(validator.iter_errors(boolean_schema)))
        with self.assertRaises(ReleaseIntegrityError):
            _validate_manifest_contract(boolean_schema)

        noncanonical_pad_bits = copy.deepcopy(base)
        noncanonical_pad_bits["authority"]["signature"] = "A" * 85 + "B=="
        self.assertTrue(list(validator.iter_errors(noncanonical_pad_bits)))
        with self.assertRaises(ReleaseIntegrityError):
            _validate_manifest_contract(noncanonical_pad_bits)

        stable = copy.deepcopy(base)
        stable["channel"] = "stable"
        self.assertTrue(list(validator.iter_errors(stable)))
        with self.assertRaises(ReleaseIntegrityError):
            _validate_manifest_contract(stable)

        restoration = copy.deepcopy(base)
        restoration.update(
            manifestType="restoration",
            targetManifestDigest="c" * 64,
            reason=" padded ",
        )
        self.assertTrue(list(validator.iter_errors(restoration)))
        with self.assertRaises(ReleaseIntegrityError):
            _validate_manifest_contract(restoration)

    def test_runtime_and_schema_reject_non_ascii_semver_digits(self) -> None:
        from guardian_core.release import ReleaseIntegrityError, _parse_semver

        schema = self._schema("release-manifest.schema.json")
        validator = Draft202012Validator(schema)
        digest = "a" * 64
        for value in ("1١.0.0", "١.0.0", "1.０.0"):
            with self.subTest(value=value):
                with self.assertRaises(ReleaseIntegrityError):
                    _parse_semver(value, "pluginVersion")
                manifest = _unsigned_manifest(
                    version=value, channel="canary", sequence=1,
                    artifact_digest=digest, source_commit=COMMIT_A,
                )
                manifest["authority"] = {
                    "schemaVersion": 1, "algorithm": "ed25519",
                    "keyId": "b" * 64, "signature": "A" * 86 + "==",
                }
                self.assertTrue(list(validator.iter_errors(manifest)))

    def test_runtime_and_schema_reject_non_ascii_timestamp_digits(self) -> None:
        from guardian_core.release import ReleaseIntegrityError, _parse_timestamp

        bad_timestamp = "2026-\u06607-15T09:00:00Z"
        with self.assertRaises(ReleaseIntegrityError):
            _parse_timestamp(bad_timestamp, "issuedAt")
        digest = "a" * 64
        manifest = _unsigned_manifest(
            version="0.1.0", channel="canary", sequence=1,
            artifact_digest=digest, source_commit=COMMIT_A,
        )
        manifest["issuedAt"] = bad_timestamp
        manifest["authority"] = {
            "schemaVersion": 1,
            "algorithm": "ed25519",
            "keyId": "b" * 64,
            "signature": "A" * 86 + "==",
        }
        validator = Draft202012Validator(self._schema("release-manifest.schema.json"))
        self.assertTrue(list(validator.iter_errors(manifest)))

    def test_state_and_history_schema_enforce_channel_specific_evidence_and_stable_semver(self) -> None:
        digest = "a" * 64
        state = {
            "schemaVersion": 1,
            "channel": "canary",
            "channelSequence": 1,
            "actionManifestDigest": digest,
            "activeManifestDigest": digest,
            "pluginVersion": "0.1.0-beta.1",
            "sourceCommit": COMMIT_A,
            "artifactDigest": digest,
            "policyDigest": EXPECTED_POLICY_SHA256,
            "canaryEvidenceDigest": None,
            "eventRecordedAt": "2026-07-15T10:00:00Z",
            "activatedAt": "2026-07-15T10:01:00Z",
            "authoritySeal": digest,
        }
        state_validator = Draft202012Validator(self._schema("release-channel-state.schema.json"))
        self.assertFalse(list(state_validator.iter_errors(state)))
        bad_canary = {**state, "canaryEvidenceDigest": digest}
        self.assertTrue(list(state_validator.iter_errors(bad_canary)))
        stable = {**state, "channel": "stable", "pluginVersion": "0.1.0", "canaryEvidenceDigest": digest}
        self.assertFalse(list(state_validator.iter_errors(stable)))
        self.assertTrue(list(state_validator.iter_errors({**stable, "canaryEvidenceDigest": None})))
        self.assertTrue(list(state_validator.iter_errors({**stable, "pluginVersion": "0.1.0-rc.1"})))

        history = {
            "schemaVersion": 1,
            "recordType": "promotion",
            "eventId": digest,
            "channel": "canary",
            "channelSequence": 1,
            "actionManifestDigest": digest,
            "activeManifestDigest": digest,
            "previousActiveManifestDigest": None,
            "pluginVersion": "0.1.0-beta.1",
            "sourceCommit": COMMIT_A,
            "artifactDigest": digest,
            "policyDigest": EXPECTED_POLICY_SHA256,
            "canaryEvidenceDigest": None,
            "authorityKeyId": digest,
            "recordedAt": "2026-07-15T10:00:00Z",
            "authoritySeal": digest,
        }
        history_validator = Draft202012Validator(self._schema("release-history-record.schema.json"))
        self.assertFalse(list(history_validator.iter_errors(history)))
        self.assertTrue(list(history_validator.iter_errors({**history, "canaryEvidenceDigest": digest})))
        stable_history = {
            **history,
            "channel": "stable",
            "pluginVersion": "0.1.0",
            "canaryEvidenceDigest": digest,
        }
        self.assertFalse(list(history_validator.iter_errors(stable_history)))
        self.assertTrue(list(history_validator.iter_errors({**stable_history, "canaryEvidenceDigest": None})))
        self.assertTrue(list(history_validator.iter_errors({**stable_history, "pluginVersion": "0.1.0-rc.1"})))


if __name__ == "__main__":
    unittest.main()

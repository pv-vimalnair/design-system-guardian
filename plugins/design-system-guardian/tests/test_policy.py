import json
import tempfile
import unittest
from pathlib import Path

from tests.guardian_test_support import catalog_authority_public_key_path


class PolicyAnchorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)
        self.public_key = catalog_authority_public_key_path(self.home)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_install_is_create_once_and_verify_succeeds(self) -> None:
        from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor, verify_policy_anchor

        self.assertEqual(install_policy_anchor(self.home, catalog_authority_public_key=self.public_key), EXPECTED_POLICY_SHA256)
        original = (self.home / "trust" / "policy-v1.json").read_bytes()
        self.assertEqual(install_policy_anchor(self.home, catalog_authority_public_key=self.public_key), EXPECTED_POLICY_SHA256)
        self.assertEqual((self.home / "trust" / "policy-v1.json").read_bytes(), original)
        self.assertEqual(verify_policy_anchor(self.home), EXPECTED_POLICY_SHA256)

    def test_missing_anchor_fails_closed(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import verify_policy_anchor

        with self.assertRaises(PolicyIntegrityError):
            verify_policy_anchor(self.home)

    def test_changed_anchor_fails_even_if_valid_json(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor, verify_policy_anchor

        install_policy_anchor(self.home, catalog_authority_public_key=self.public_key)
        anchor = self.home / "trust" / "policy-v1.json"
        policy = json.loads(anchor.read_text(encoding="utf-8"))
        policy["denyWins"] = False
        anchor.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaises(PolicyIntegrityError):
            verify_policy_anchor(self.home)

    def test_changed_seal_fails(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor, verify_policy_anchor

        install_policy_anchor(self.home, catalog_authority_public_key=self.public_key)
        (self.home / "trust" / "policy-v1.sha256").write_text("0" * 64 + "\n", encoding="ascii")
        with self.assertRaises(PolicyIntegrityError):
            verify_policy_anchor(self.home)

    def test_partial_existing_anchor_is_never_overwritten(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor

        trust = self.home / "trust"
        trust.mkdir(parents=True)
        anchor = trust / "policy-v1.json"
        anchor.write_text('{"foreign":true}', encoding="utf-8")
        with self.assertRaises(PolicyIntegrityError):
            install_policy_anchor(self.home, catalog_authority_public_key=self.public_key)
        self.assertEqual(anchor.read_text(encoding="utf-8"), '{"foreign":true}')

    def test_shipped_policy_and_expected_digest_match(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.policy import EXPECTED_POLICY_SHA256, shipped_policy, shipped_policy_path

        self.assertEqual(sha256_digest(shipped_policy()), EXPECTED_POLICY_SHA256)
        self.assertTrue(shipped_policy_path().is_file())


class GuardianPathTest(unittest.TestCase):
    def test_profile_ids_are_isolated_and_traversal_is_rejected(self) -> None:
        from guardian_core.paths import GuardianPaths

        paths = GuardianPaths(Path("guardian-home"))
        self.assertEqual(paths.profile("example-company").name, "example-company")
        for unsafe in ("../other", "ExampleCompany", "a/b", "", "a_b", ".", "a" * 64):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    paths.profile(unsafe)

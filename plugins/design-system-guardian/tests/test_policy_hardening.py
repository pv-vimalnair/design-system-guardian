import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import catalog_authority_public_key_path


def install_test_policy(home: Path):
    from guardian_core.policy import install_policy_anchor

    return install_policy_anchor(
        home,
        catalog_authority_public_key=catalog_authority_public_key_path(home),
    )


class PolicyHardeningTest(unittest.TestCase):
    def test_duplicate_keys_are_rejected_even_when_last_value_matches(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor, verify_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            install_test_policy(home)
            anchor = home / "trust" / "policy-v1.json"
            text = anchor.read_text(encoding="utf-8")
            anchor.write_text(
                text.replace('"denyWins":true', '"denyWins":false,"denyWins":true'),
                encoding="utf-8",
            )
            with self.assertRaises(PolicyIntegrityError):
                verify_policy_anchor(home)

    def test_noncanonical_byte_change_is_rejected(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor, verify_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            install_test_policy(home)
            anchor = home / "trust" / "policy-v1.json"
            anchor.write_bytes(anchor.read_bytes() + b"\n")
            with self.assertRaises(PolicyIntegrityError):
                verify_policy_anchor(home)

    def test_failed_seal_write_leaves_no_partial_trust_anchor(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with patch("guardian_core.policy.atomic_write_bytes", side_effect=OSError("simulated")):
                with self.assertRaises(PolicyIntegrityError):
                    install_test_policy(home)
            self.assertFalse((home / "trust").exists())
            self.assertEqual(list(home.glob(".trust.*")), [])

    def test_repeat_install_reports_verified_not_created(self) -> None:
        from guardian_core.policy import install_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            first = install_test_policy(Path(directory))
            second = install_test_policy(Path(directory))
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(first.digest, second.digest)

    def test_symlinked_home_is_rejected_when_supported(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            try:
                linked.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("Directory symlink creation is not permitted on this Windows host")
            with self.assertRaises(PolicyIntegrityError):
                install_test_policy(linked)

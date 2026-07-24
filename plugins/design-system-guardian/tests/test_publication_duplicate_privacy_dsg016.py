"""End-to-end public-release privacy coverage for working-file identities."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.test_publication_privacy_dsg014 import checker_module, commit, make_repo, write


class DuplicatePrivacyFieldTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = checker_module()

    def test_canonical_asset_key_is_scanned_as_private_identifier_evidence(self) -> None:
        value = "company-component-key-7e43c9f8"
        identifiers = set(self.checker._walk_identifiers({"canonicalAssetKey": value}))
        self.assertEqual(identifiers, {value})

    def test_current_tree_and_reachable_history_leaks_are_rejected_and_redacted(self) -> None:
        identifiers = {
            "fileKey": "company-working-file-7e43c9f8",
            "nodeId": "company-node-7e43c9f8",
            "canonicalAssetKey": "company-component-key-7e43c9f8",
        }
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = make_repo(base)
            relative = "plugins/design-system-guardian/docs/working-copy.json"
            payload = json.dumps(identifiers) + "\n"
            write(root, relative, payload)
            commit(root, "fixture working-copy evidence")
            home = base / "private-home"
            write(home, "profiles/private.json", payload)

            current = self.checker.check_public_release(
                root,
                history=False,
                local_home=home,
                require_clean=True,
                check_prior_suite=False,
            )
            rendered = self.checker.render_result(current)
            self.assertFalse(current.ok)
            self.assertIn("local_identifier_match", current.codes)
            for value in identifiers.values():
                self.assertNotIn(value, rendered)

            (root / relative).unlink()
            commit(root, "remove fixture working-copy evidence")
            history = self.checker.check_public_release(
                root,
                history=True,
                local_home=home,
                require_clean=True,
                check_prior_suite=False,
            )
            rendered_history = self.checker.render_result(history)
            self.assertFalse(history.ok)
            self.assertTrue(
                {"history_violation", "local_identifier_match"}.intersection(history.codes)
            )
            for value in identifiers.values():
                self.assertNotIn(value, rendered_history)


if __name__ == "__main__":
    unittest.main()

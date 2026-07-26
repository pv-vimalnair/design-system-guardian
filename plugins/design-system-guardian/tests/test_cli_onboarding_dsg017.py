from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_onboarding_dsg017 import file_state, onboarding_bundle
from tests.test_profile_snapshot import NOW


class GuardianOnboardingCliTest(unittest.TestCase):
    def test_status_preview_permission_and_apply_form_one_local_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            bundle = onboarding_bundle(root)
            candidate = {
                key: copy.deepcopy(bundle[key])
                for key in (
                    "schemaVersion",
                    "catalogAuthorityPublicKey",
                    "profile",
                    "catalog",
                )
            }
            candidate_path = root / "candidate.json"
            write_canonical(candidate_path, candidate)

            code, status = invoke(home, ["setup", "status", "--profile", "example-company"])
            self.assertEqual(code, 4)
            self.assertEqual(status["reasonCode"], "policy_anchor_missing")
            self.assertFalse(home.exists())

            code, preview = invoke(home, ["setup", "preview", "--input", str(candidate_path)])
            self.assertEqual(code, 4)
            self.assertEqual(preview["status"], "permission_required")
            self.assertFalse(home.exists())

            permitted = {**candidate, "permission": {**preview["permissionBinding"], "granted": True}}
            permitted_path = root / "permitted.json"
            write_canonical(permitted_path, permitted)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                code, applied = invoke(home, ["setup", "apply", "--input", str(permitted_path)])
            self.assertEqual(code, 0)
            self.assertTrue(applied["ready"])
            before = file_state(home)

            with patch("guardian_core.onboarding._utc_now", return_value=NOW):
                code, ready = invoke(home, ["setup", "status", "--profile", "example-company"])
            self.assertEqual(code, 0)
            self.assertEqual(ready["status"], "ready")
            self.assertEqual(file_state(home), before)

    def test_invalid_or_denied_bundle_reports_unchanged_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            denied = onboarding_bundle(root)
            denied["permission"]["granted"] = False
            path = root / "denied.json"
            write_canonical(path, denied)

            code, result = invoke(home, ["setup", "apply", "--input", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(result["reasonCode"], "onboarding_invalid")
            self.assertFalse(result["localChangesPerformed"])
            self.assertFalse(home.exists())


if __name__ == "__main__":
    unittest.main()

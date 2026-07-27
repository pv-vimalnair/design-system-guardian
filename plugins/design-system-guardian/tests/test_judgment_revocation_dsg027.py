from __future__ import annotations
import unittest
from unittest.mock import patch
from tests.test_judgment_decisions_dsg027 import candidate, provision_home

class JudgmentRevocationTest(unittest.TestCase):
    def test_revocation_is_append_only_and_idempotent(self):
        from guardian_core.judgment_decisions import apply_judgment_decision, preview_judgment_decision, read_judgment_status, revoke_judgment_decision
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=candidate())
            apply_judgment_decision(home, {"schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(), "permission": {**preview["permissionBinding"], "granted": True}})
            status = read_judgment_status(home, profile_id=profile, run_id=run)
            history = home / "profiles" / profile / "audits" / run / "judgment-history"
            approval = next(history.glob("00000001-*.json")); before = approval.read_bytes()
            bundle = {"schemaVersion": 1, "profileId": profile, "runId": run,
                "permission": {**status["revocationPermissionBinding"], "granted": True}}
            self.assertTrue(revoke_judgment_decision(home, bundle)["changed"])
            self.assertFalse(revoke_judgment_decision(home, bundle)["changed"])
            self.assertEqual(approval.read_bytes(), before)
            self.assertEqual(len(list(history.glob("*.json"))), 2)
            revoked = read_judgment_status(home, profile_id=profile, run_id=run)
            self.assertEqual((revoked["status"], revoked["effectiveProjection"]["effectiveStatus"]), ("revoked", "conflict"))
            preview = preview_judgment_decision(
                home, profile_id=profile, run_id=run, candidate=candidate()
            )
            self.assertEqual(preview["permissionBinding"]["sequence"], 3)
            apply_judgment_decision(home, {"schemaVersion": 1, "profileId": profile,
                "runId": run, "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": True}})
            self.assertEqual(read_judgment_status(home, profile_id=profile, run_id=run)["status"], "active")
            self.assertEqual(len(list(history.glob("*.json"))), 3)

    def test_interrupted_revocation_revalidates_retained_assessment(self):
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError, apply_judgment_decision,
            preview_judgment_decision, read_judgment_status,
            revoke_judgment_decision,
        )
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(
                home, profile_id=profile, run_id=run, candidate=candidate()
            )
            apply_judgment_decision(home, {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": True},
            })
            status = read_judgment_status(home, profile_id=profile, run_id=run)
            bundle = {"schemaVersion": 1, "profileId": profile, "runId": run,
                "permission": {**status["revocationPermissionBinding"], "granted": True}}
            with patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError("interrupted"),
            ):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    revoke_judgment_decision(home, bundle)
            audit = home / "profiles" / profile / "audits" / run
            (audit / "current-judgment-history.json").unlink()
            (audit / "judgment-assessment.sealed.json").unlink()
            with self.assertRaises(JudgmentDecisionIntegrityError):
                revoke_judgment_decision(home, bundle)
if __name__ == "__main__": unittest.main()

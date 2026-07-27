from __future__ import annotations
import copy
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

    def test_interrupted_reapproval_preserves_revoked_prefix_and_recovers(self):
        from guardian_core.canonical import atomic_write_json
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError, _head, _read_history,
            apply_judgment_decision, preview_judgment_decision,
            read_judgment_status, revoke_judgment_decision,
        )

        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            first_preview = preview_judgment_decision(
                home, profile_id=profile, run_id=run, candidate=candidate()
            )
            apply_judgment_decision(home, {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(),
                "permission": {
                    **first_preview["permissionBinding"], "granted": True,
                },
            })
            active = read_judgment_status(
                home, profile_id=profile, run_id=run
            )
            revoke_judgment_decision(home, {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "permission": {
                    **active["revocationPermissionBinding"], "granted": True,
                },
            })
            reapproval_candidate = candidate()
            reapproval_candidate["reason"] = "Exact reapproval after revocation."
            reapproval_preview = preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run,
                candidate=reapproval_candidate,
            )
            bundle = {
                "schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": reapproval_candidate,
                "permission": {
                    **reapproval_preview["permissionBinding"], "granted": True,
                },
            }
            audit = home / "profiles" / profile / "audits" / run
            history = audit / "judgment-history"
            head = audit / "current-judgment-history.json"
            head_before = head.read_bytes()
            records_before = {
                path.name: path.read_bytes()
                for path in sorted(history.glob("*.json"))
            }
            with patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError("interrupted"),
            ):
                with self.assertRaises(JudgmentDecisionIntegrityError) as interrupted:
                    apply_judgment_decision(home, bundle)
            self.assertTrue(interrupted.exception.local_changes_performed)
            self.assertEqual(head.read_bytes(), head_before)
            records_after = sorted(history.glob("*.json"))
            self.assertEqual(len(records_after), 3)
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in records_after[:2]
                },
                records_before,
            )
            with self.assertRaises(JudgmentDecisionIntegrityError):
                _read_history(home, profile, run)
            partial_records, partial_head = _read_history(
                home, profile, run, allow_partial=True
            )
            self.assertIsNone(partial_head)
            self.assertEqual(
                [record["recordType"] for record in partial_records],
                ["approval", "revocation", "approval"],
            )
            partial_bytes = {
                path.name: path.read_bytes() for path in records_after
            }
            mismatched_prefix = copy.deepcopy(partial_records[-2])
            mismatched_prefix["assessmentDigest"] = "0" * 64
            invalid_prefix_heads = {
                "more_than_one_sequence_behind": _head(
                    home,
                    partial_records[0],
                    partial_records[0]["decisionDigest"],
                ),
                "wrong_prefix_active_decision": _head(
                    home,
                    partial_records[-2],
                    partial_records[0]["decisionDigest"],
                ),
                "mismatched_prefix_assessment": _head(
                    home,
                    mismatched_prefix,
                    None,
                ),
            }
            for label, invalid_head in invalid_prefix_heads.items():
                with self.subTest(prefix_head=label):
                    atomic_write_json(head, invalid_head)
                    with self.assertRaises(JudgmentDecisionIntegrityError):
                        _read_history(
                            home, profile, run, allow_partial=True
                        )
                    self.assertEqual(
                        {
                            path.name: path.read_bytes()
                            for path in sorted(history.glob("*.json"))
                        },
                        partial_bytes,
                    )
            head.write_bytes(head_before)

            divergent = copy.deepcopy(bundle)
            divergent["candidate"]["reason"] = "Divergent reapproval."
            with self.assertRaises(JudgmentDecisionIntegrityError) as rejected:
                apply_judgment_decision(home, divergent)
            self.assertFalse(rejected.exception.local_changes_performed)
            self.assertEqual(head.read_bytes(), head_before)
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in sorted(history.glob("*.json"))
                },
                partial_bytes,
            )

            recovered = apply_judgment_decision(home, bundle)
            self.assertTrue(recovered["changed"])
            self.assertEqual(recovered["status"], "active")
            self.assertNotEqual(head.read_bytes(), head_before)
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in sorted(history.glob("*.json"))
                },
                partial_bytes,
            )
            self.assertEqual(
                read_judgment_status(
                    home, profile_id=profile, run_id=run
                )["status"],
                "active",
            )

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
            audit = home / "profiles" / profile / "audits" / run
            head = audit / "current-judgment-history.json"
            head_before = head.read_bytes()
            with patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError("interrupted"),
            ):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    revoke_judgment_decision(home, bundle)
            self.assertTrue(head.is_file())
            self.assertEqual(head.read_bytes(), head_before)
            (audit / "judgment-assessment.sealed.json").unlink()
            with self.assertRaises(JudgmentDecisionIntegrityError):
                revoke_judgment_decision(home, bundle)
if __name__ == "__main__": unittest.main()

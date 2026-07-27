from __future__ import annotations

import copy
import unittest

from guardian_core.canonical import sha256_digest
from guardian_core.judgment_assessment import (
    build_judgment_assessment,
    derive_effective_judgment,
)
from tests.test_judgment_assessment_dsg027 import conflict_candidate
from tests.test_judgment_decisions_dsg027 import provision_home


def assessment_with_two_findings(context: dict) -> dict:
    first = conflict_candidate()
    second = copy.deepcopy(first["findings"][0])
    second["explanation"] = "The secondary action masks the confirmation state."
    second["impact"] = "The reviewed flow can appear unfinished."
    second["correction"] = "Separate confirmation from the secondary action."
    second["evidenceReferences"] = [
        {"artifact": "review-capture", "digest": "8" * 64}
    ]
    first["findings"].append(second)
    return build_judgment_assessment(
        run_pin=context["runPin"],
        rule_snapshot=context["ruleSnapshot"],
        analysis_attestation=context["analysisAttestation"],
        audit_result=context["auditResult"],
        candidate_results=[first],
    )


class JudgmentProjectionReportTest(unittest.TestCase):
    def test_report_preserves_raw_findings_and_separates_effective_authority(self) -> None:
        from guardian_core.run_artifacts import render_judgment_report

        temporary, _, context = provision_home()
        self.addCleanup(temporary.cleanup)
        assessment = assessment_with_two_findings(context)
        finding_ids = [
            finding["findingId"]
            for instance in assessment["instances"]
            for finding in instance["findings"]
        ]
        selected = finding_ids[:1]
        projection = derive_effective_judgment(
            assessment,
            {
                "active": True,
                "assessmentDigest": sha256_digest(assessment),
                "selectedFindingIds": selected,
            },
            enforcement_authority_lane=context["runManifest"]["enforcementAuthorityLane"],
        )
        status = {
            "schemaVersion": 1,
            "status": "active",
            "profileId": assessment["profileId"],
            "runId": assessment["runId"],
            "assessment": assessment,
            "historyHead": {"activeDecisionDigest": "9" * 64},
            "effectiveProjection": projection,
            "revocationPermissionBinding": {"action": "revoke"},
            "localChangesPerformed": False,
            "productionReady": False,
        }

        report = render_judgment_report(status)

        self.assertIn("Raw judgment: conflict", report)
        self.assertIn("Effective judgment: conflict", report)
        self.assertIn("Protected enforcement authority: not_assessed", report)
        self.assertIn("Production ready: false", report)
        self.assertIn("Revocation state: active exception; revocation available", report)
        self.assertIn(f"Selected finding IDs: {selected[0]}", report)
        self.assertIn(f"Unselected finding IDs: {finding_ids[1]}", report)
        self.assertIn("Passed through a user-approved exception", report)
        self.assertIn("The primary hierarchy competes with the secondary action.", report)
        self.assertIn("The intended next action is harder to identify.", report)
        self.assertIn("Reduce the secondary action emphasis and evaluate again.", report)
        self.assertIn("The secondary action masks the confirmation state.", report)

    def test_revoked_report_has_no_applied_exception_and_renderer_is_pure(self) -> None:
        from guardian_core.run_artifacts import render_judgment_report

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        assessment = assessment_with_two_findings(context)
        projection = derive_effective_judgment(
            assessment,
            {
                "active": False,
                "assessmentDigest": sha256_digest(assessment),
                "selectedFindingIds": [],
            },
            enforcement_authority_lane=context["runManifest"]["enforcementAuthorityLane"],
        )
        audit_report = (
            home
            / "profiles"
            / assessment["profileId"]
            / "audits"
            / assessment["runId"]
            / "audit-report.md"
        )
        audit_report.parent.mkdir(parents=True)
        audit_report.write_bytes(b"immutable audit report\n")
        before = {
            path.relative_to(home).as_posix(): path.read_bytes()
            for path in home.rglob("*")
            if path.is_file()
        }
        status = {
            "schemaVersion": 1,
            "status": "revoked",
            "profileId": assessment["profileId"],
            "runId": assessment["runId"],
            "assessment": assessment,
            "historyHead": {"activeDecisionDigest": None},
            "effectiveProjection": projection,
            "revocationPermissionBinding": None,
            "localChangesPerformed": False,
            "productionReady": False,
        }

        report = render_judgment_report(status)
        after = {
            path.relative_to(home).as_posix(): path.read_bytes()
            for path in home.rglob("*")
            if path.is_file()
        }

        self.assertEqual(before, after)
        self.assertEqual(audit_report.read_bytes(), b"immutable audit report\n")
        self.assertIn("Revocation state: revoked", report)
        self.assertNotIn("Passed through a user-approved exception", report)
        self.assertIn("Production ready: false", report)


if __name__ == "__main__":
    unittest.main()

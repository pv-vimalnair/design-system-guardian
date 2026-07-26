"""Readable v0.3.3 audit-report projection tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.test_finalize_artifacts_dsg003 import clean_audit, provision_run


def _trusted_check(
    *,
    check_id: str,
    scope: str,
    status: str = "allowed",
) -> dict:
    reason = None if status == "allowed" else f"ux_{scope}_gap"
    message = {
        "allowed": "UX/accessibility evidence satisfied the required check.",
        "gap": "UX/accessibility evidence did not satisfy the required check.",
    }[status]
    return {
        "checkId": check_id,
        "area": "hierarchy" if scope == "screen" else "navigation",
        "status": status,
        "message": message,
        "evidence": {
            "scope": scope,
            "targetDigest": ("c" if scope == "screen" else "d") * 64,
            "evidenceDigest": "e" * 64,
            "reasonCode": reason,
            "evaluatorDigest": "f" * 64,
            "sourceCutDigest": "a" * 64,
        },
    }


class ReadableAuditReportV033Test(unittest.TestCase):
    def _render(self, home: Path, audit: dict) -> str:
        from guardian_core.run_artifacts import render_audit_report, seal_run_artifact

        envelope = seal_run_artifact(
            home,
            artifact_type="audit-result",
            profile_id=audit["profileId"],
            run_id=audit["runId"],
            payload=audit,
        )
        return render_audit_report(home, envelope)

    def test_report_separates_all_three_lanes_and_keeps_v032_ux_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            audit = clean_audit(provision_run(home)).result

            report = self._render(home, audit)

            self.assertIn("## Design-system compliance lane", report)
            self.assertIn("## UX/accessibility lane", report)
            self.assertIn("## Protected production authority lane", report)
            self.assertIn("### Screen checks", report)
            self.assertIn("### Final-flow checks", report)
            self.assertIn("Legacy evaluator status:", report)
            self.assertIn(
                "Next action: Complete the final screen-and-flow UX/accessibility evaluation.",
                report,
            )

    def test_trusted_checks_are_grouped_by_scope_without_raw_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            audit = clean_audit(provision_run(home)).result
            audit["uxAccessibilityLane"] = {
                "status": "allowed",
                "checks": [
                    _trusted_check(check_id="screen-hierarchy", scope="screen"),
                    _trusted_check(check_id="flow-navigation", scope="flow"),
                ],
            }

            report = self._render(home, audit)

            screen_section, flow_section = report.split("### Final-flow checks", maxsplit=1)
            self.assertIn("screen-hierarchy", screen_section)
            self.assertNotIn("flow-navigation", screen_section)
            self.assertIn("flow-navigation", flow_section)
            self.assertNotIn("targetDigest", report)
            self.assertNotIn("evidenceDigest", report)
            self.assertNotIn("c" * 64, report)
            self.assertNotIn("e" * 64, report)
            self.assertIn(
                "Next action: Run the sealed result through a host with protected production authority.",
                report,
            )

    def test_figma_report_labels_local_binding_as_workspace_not_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            audit = clean_audit(provision_run(home)).result
            audit["coverage"]["adapter"] = "figma"

            report = self._render(home, audit)

            self.assertIn("Bound local evidence workspace:", report)
            self.assertNotIn("Intended project:", report)
            self.assertNotIn("Figma document:", report)

    def test_next_action_prioritizes_design_then_ux_then_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            audit = clean_audit(provision_run(home)).result
            audit["designSystemLane"]["status"] = "conflict"
            audit["designSystemLane"]["violations"] = [
                {
                    "category": "colors",
                    "diagnosticId": "raw-color",
                    "message": "A raw value was found.",
                    "kind": "violation",
                    "evidence": {"privateNodeName": "do-not-project"},
                }
            ]
            audit["uxAccessibilityLane"] = {
                "status": "conflict",
                "checks": [
                    _trusted_check(
                        check_id="screen-hierarchy",
                        scope="screen",
                        status="gap",
                    ),
                    _trusted_check(
                        check_id="flow-navigation",
                        scope="flow",
                        status="gap",
                    ),
                ],
            }

            report = self._render(home, audit)

            self.assertIn(
                "Next action: Fix the reported design-system violations, then run the final audit again.",
                report,
            )
            self.assertNotIn("privateNodeName", report)
            self.assertNotIn("do-not-project", report)


if __name__ == "__main__":
    unittest.main()

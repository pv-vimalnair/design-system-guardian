import copy
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)
POLICY_DIGEST = "a" * 64
SOURCE_CUT = {
    "figmaFiles": [{"fileKey": "figma-brand", "version": "42"}],
    "catalogDigest": "b" * 64,
    "codeConnectParseDigest": "c" * 64,
    "repositoryCommit": "abc1234",
    "componentCatalogBuild": "build-7",
}
def sample_project_binding() -> dict:
    from guardian_core.project_binding import capture_project_binding

    return capture_project_binding(Path(__file__).resolve().parents[1])


def sample_project_evidence() -> dict:
    return {
        **sample_project_binding(),
        "assessedTreeDigest": "f" * 64,
        "analysisInputsDigest": "9" * 64,
    }



def sample_pin(*, source_state: str = "fresh") -> dict:
    return {
        "schemaVersion": 1,
        "runId": "run-audit-1",
        "profileId": "example-company",
        "snapshotId": "d" * 64,
        "policyDigest": POLICY_DIGEST,
        "sourceCut": copy.deepcopy(SOURCE_CUT),
        "sourceState": source_state,
        "projectBinding": sample_project_binding(),
    }


def complete_adapter(*, diagnostics: list[dict] | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "adapter": "flutter",
        "supported": True,
        "configDigest": "e" * 64,
        "sourceCut": copy.deepcopy(SOURCE_CUT),
        "assessedFiles": 3,
        "totalFiles": 3,
        "categories": {
            category: {"status": "allowed", "assessedItems": 1, "totalItems": 1}
            for category in CATEGORIES
        },
        "diagnostics": diagnostics or [],
    }


def sample_snapshot() -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "profileId": "example-company",
        "snapshotId": "d" * 64,
        "sourceCut": copy.deepcopy(SOURCE_CUT),
        "sourceState": "fresh",
        "sourceComplete": True,
        "sourceAvailable": True,
        "createdAt": now,
        "refreshAttemptedAt": now,
        "lastSuccessfulRefreshAt": now,
        "sourceEvidence": {"refreshAttempted": True},
        "tokens": {},
        "registry": {"components": [], "icons": []},
    }


def allowed_ux_check() -> dict:
    return {
        "checkId": "ux-hierarchy",
        "area": "hierarchy",
        "status": "allowed",
        "message": "Hierarchy was assessed.",
        "evidence": {"review": "complete"},
    }


class AuditEvaluationTest(unittest.TestCase):
    def test_empty_resolution_audit_reclassifies_current_source_state(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.contracts import ExitCode

        audit_now = datetime.now(timezone.utc)

        def timestamp(value: datetime) -> str:
            return value.isoformat().replace("+00:00", "Z")

        cases = (
            ("stale", True, True, timestamp(audit_now - timedelta(days=8))),
            ("source_unavailable", False, True, timestamp(audit_now - timedelta(days=4))),
            ("source_incomplete", True, False, timestamp(audit_now - timedelta(hours=1))),
        )
        for expected, available, complete, last_success in cases:
            with self.subTest(expected=expected):
                snapshot = sample_snapshot()
                snapshot.update(
                    {
                        "createdAt": timestamp(audit_now - timedelta(minutes=30)),
                        "refreshAttemptedAt": timestamp(audit_now - timedelta(minutes=30)),
                        "lastSuccessfulRefreshAt": last_success,
                        "sourceAvailable": available,
                        "sourceComplete": complete,
                        "sourceEvidence": {"refreshAttempted": True},
                    }
                )
                result = evaluate_audit(
                    run_pin=sample_pin(source_state="fresh"),
                    adapter_result=complete_adapter(),
                    resolutions=[],
                    ux_checks=[allowed_ux_check()],
                    project_evidence=sample_project_evidence(),
                    verified_snapshot=snapshot,
                )

                self.assertEqual(
                    result.exit_code,
                    ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE,
                )
                self.assertEqual(result.result["designSystemLane"]["status"], expected)
                self.assertFalse(result.result["productionReady"])

    def test_clean_design_lane_is_deterministic_but_untrusted_ux_blocks_pass(self) -> None:
        from guardian_core.audit import AUDIT_CATEGORIES, evaluate_audit
        from guardian_core.contracts import ExitCode

        first = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        second = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        self.assertEqual(first, second)
        self.assertEqual(AUDIT_CATEGORIES, CATEGORIES)
        self.assertEqual(first.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertFalse(first.result["productionReady"])
        self.assertEqual(first.result["designSystemLane"]["status"], "allowed")
        self.assertEqual(first.result["uxAccessibilityLane"]["status"], "not_assessed")
        self.assertEqual(set(first.result["coverage"]["categories"]), set(CATEGORIES))

    def test_incomplete_category_and_unassessed_ux_never_pass(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.contracts import ExitCode

        adapter = complete_adapter()
        adapter["categories"]["motion"] = {
            "status": "not_assessed",
            "assessedItems": 0,
            "totalItems": 1,
        }
        result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=adapter,
            resolutions=[],
            ux_checks=[],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertFalse(result.result["productionReady"])
        self.assertFalse(result.result["coverage"]["complete"])
        self.assertEqual(result.result["coverage"]["status"], "not_assessed")
        self.assertEqual(result.result["uxAccessibilityLane"]["status"], "not_assessed")

    def test_raw_and_equal_value_diagnostics_are_violations(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.contracts import ExitCode

        diagnostics = [
            {
                "diagnosticId": "equal-value-blue",
                "category": "colors",
                "kind": "violation",
                "message": "Equal-looking raw value is not connected to the approved token.",
                "evidence": {"rule": "equal_value_literal"},
            },
            {
                "diagnosticId": "raw-spacing",
                "category": "spacing",
                "kind": "violation",
                "message": "Raw spacing is forbidden.",
                "evidence": {"rule": "raw_value"},
            },
        ]
        result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(diagnostics=list(reversed(diagnostics))),
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertFalse(result.result["productionReady"])
        self.assertEqual(
            [item["diagnosticId"] for item in result.result["designSystemLane"]["violations"]],
            ["equal-value-blue", "raw-spacing"],
        )

    def test_inaccessible_approved_asset_is_a_design_system_gap(self) -> None:
        from guardian_core.audit import evaluate_audit

        diagnostic = {
            "diagnosticId": "approved-contrast-gap",
            "category": "colors",
            "kind": "design_system_gap",
            "message": "Approved foreground and background do not meet contrast requirements.",
            "evidence": {
                "approvedIdentity": "color.text.muted",
                "requiredAction": "request_design_system_change",
            },
        }
        result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(diagnostics=[diagnostic]),
            resolutions=[],
            ux_checks=[
                {
                    "checkId": "contrast-check",
                    "area": "accessibility",
                    "status": "gap",
                    "message": "Approved token fails contrast.",
                    "evidence": {"approvedIdentity": "color.text.muted"},
                }
            ],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        gap = result.result["designSystemLane"]["gaps"][0]
        self.assertEqual(gap["diagnosticId"], "approved-contrast-gap")
        self.assertEqual(gap["evidence"]["requiredAction"], "request_design_system_change")
        self.assertNotIn("replacement", gap["evidence"])
        self.assertEqual(result.result["uxAccessibilityLane"]["status"], "not_assessed")

    def test_exit_precedence_is_integrity_then_source_then_coverage_then_violation(self) -> None:
        from guardian_core.audit import AuditIntegrityError, evaluate_audit
        from guardian_core.contracts import ExitCode

        adapter = complete_adapter(
            diagnostics=[
                {
                    "diagnosticId": "raw-color",
                    "category": "colors",
                    "kind": "violation",
                    "message": "Raw color.",
                    "evidence": {},
                }
            ]
        )
        adapter["supported"] = False
        adapter["categories"]["motion"]["status"] = "unsupported"
        stale_snapshot = sample_snapshot()
        audit_now = datetime.now(timezone.utc)
        stale_snapshot.update(
            {
                "createdAt": (audit_now - timedelta(hours=1)).isoformat(),
                "refreshAttemptedAt": (audit_now - timedelta(hours=1)).isoformat(),
                "lastSuccessfulRefreshAt": (audit_now - timedelta(days=8)).isoformat(),
            }
        )
        result = evaluate_audit(
            run_pin=sample_pin(source_state="fresh"),
            adapter_result=adapter,
            resolutions=[],
            ux_checks=[],
            project_evidence=sample_project_evidence(),
            verified_snapshot=stale_snapshot,
        )
        self.assertEqual(result.exit_code, ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)

        mismatched = complete_adapter()
        mismatched["sourceCut"]["repositoryCommit"] = "different"
        with self.assertRaises(AuditIntegrityError) as raised:
            evaluate_audit(
                run_pin=sample_pin(),
                adapter_result=mismatched,
                resolutions=[],
                ux_checks=[allowed_ux_check()],
                project_evidence=sample_project_evidence(),
                verified_snapshot=sample_snapshot(),
            )
        self.assertEqual(raised.exception.exit_code, ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)

    def test_sentinel_always_blocks_production_with_unassessed_ux(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.contracts import ExitCode
        from guardian_core.sentinels import make_sentinel

        resolution = {
            "schemaVersion": 1,
            "status": "missing",
            "profileId": "example-company",
            "snapshotId": "d" * 64,
            "request": {"requestId": "missing-icon", "kind": "icon", "identity": "icon.none"},
            "selectedIdentity": None,
            "evidence": {"reason": "proven_absent_from_fresh_complete_snapshot"},
            "sentinel": make_sentinel(
                kind="icon", request_id="missing-icon", policy_digest=POLICY_DIGEST
            ),
        }
        result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[resolution],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertFalse(result.result["productionReady"])
        self.assertEqual(result.result["designSystemLane"]["sentinelCount"], 1)

    def test_forged_sentinel_style_is_rejected(self) -> None:
        from guardian_core.audit import AuditIntegrityError, evaluate_audit
        from guardian_core.sentinels import make_sentinel

        sentinel = make_sentinel(
            kind="icon", request_id="missing-icon", policy_digest=POLICY_DIGEST
        )
        sentinel["diagnosticStyle"]["background"] = "#0000FF"
        resolution = {
            "schemaVersion": 1,
            "status": "missing",
            "profileId": "example-company",
            "snapshotId": "d" * 64,
            "request": {"requestId": "missing-icon", "kind": "icon", "identity": "icon.none"},
            "selectedIdentity": None,
            "evidence": {"reason": "proven_absent_from_fresh_complete_snapshot"},
            "sentinel": sentinel,
        }
        with self.assertRaises(AuditIntegrityError):
            evaluate_audit(
                run_pin=sample_pin(), adapter_result=complete_adapter(),
                resolutions=[resolution], ux_checks=[allowed_ux_check()],
                project_evidence=sample_project_evidence(),
                verified_snapshot=sample_snapshot(),
            )


if __name__ == "__main__":
    unittest.main()

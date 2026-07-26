from __future__ import annotations

import unittest
from unittest.mock import patch

from tests.test_audit_dsg003 import (
    complete_adapter,
    sample_pin,
    sample_project_evidence,
    sample_snapshot,
)


class AuditLaneSeparationTest(unittest.TestCase):
    def test_ux_conflict_does_not_change_a_clean_design_system_lane(self) -> None:
        from guardian_core.audit import evaluate_audit

        ux_check = {
            "checkId": "ux-final-flow-recovery",
            "area": "recovery",
            "status": "gap",
            "message": "The final flow has a recovery gap.",
            "evidence": {"reasonCode": "ux_flow_gap"},
        }
        with patch(
            "guardian_core.audit._validate_ux_checks",
            return_value=([ux_check], "conflict"),
        ):
            evaluation = evaluate_audit(
                run_pin=sample_pin(),
                adapter_result=complete_adapter(),
                resolutions=[],
                ux_checks=[],
                project_evidence=sample_project_evidence(),
                verified_snapshot=sample_snapshot(),
            )

        self.assertEqual(evaluation.result["designSystemLane"]["status"], "allowed")
        self.assertEqual(evaluation.result["uxAccessibilityLane"]["status"], "conflict")
        self.assertFalse(evaluation.result["productionReady"])

    def test_built_in_final_flow_is_revalidated_and_keeps_lanes_separate(self) -> None:
        from guardian_core.audit import derive_audit_exit_code, evaluate_audit
        from guardian_core.contracts import ExitCode
        from guardian_core.ux_evaluator import (
            REQUIRED_FLOW_AREAS,
            REQUIRED_SCREEN_AREAS,
            audit_checks_from_evaluation,
            evaluate_final_flow,
        )

        screen_digest = "1" * 64
        flow_digest = "2" * 64

        def observation(target_digest: str, area: str, *, passed: bool = True) -> dict:
            return {
                "checkId": f"{target_digest[:8]}-{area}",
                "targetDigest": target_digest,
                "area": area,
                "operator": "equals",
                "observed": passed,
                "expected": True,
                "evidenceDigest": ("3" if passed else "4") * 64,
            }

        observations = [
            *(observation(screen_digest, area) for area in REQUIRED_SCREEN_AREAS),
            *(observation(flow_digest, area) for area in REQUIRED_FLOW_AREAS),
        ]
        evaluation = evaluate_final_flow(
            target={"flowDigest": flow_digest, "screenDigests": [screen_digest]},
            observations=observations,
            source_cut=sample_pin()["sourceCut"],
        )
        trusted_checks = audit_checks_from_evaluation(
            evaluation,
            target={"flowDigest": flow_digest, "screenDigests": [screen_digest]},
            source_cut=sample_pin()["sourceCut"],
        )
        result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[],
            trusted_ux_checks=trusted_checks,
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        self.assertEqual(result.result["designSystemLane"]["status"], "allowed")
        self.assertEqual(result.result["uxAccessibilityLane"]["status"], "not_assessed")
        self.assertEqual(
            result.exit_code,
            ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE,
        )
        self.assertEqual(derive_audit_exit_code(result.result), result.exit_code)

        gap_observations = list(observations)
        gap_observations[-1] = observation(
            flow_digest,
            REQUIRED_FLOW_AREAS[-1],
            passed=False,
        )
        gap_evaluation = evaluate_final_flow(
            target={"flowDigest": flow_digest, "screenDigests": [screen_digest]},
            observations=gap_observations,
            source_cut=sample_pin()["sourceCut"],
        )
        gap_result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[],
            trusted_ux_checks=audit_checks_from_evaluation(
                gap_evaluation,
                target={"flowDigest": flow_digest, "screenDigests": [screen_digest]},
                source_cut=sample_pin()["sourceCut"],
            ),
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        self.assertEqual(gap_result.result["designSystemLane"]["status"], "allowed")
        self.assertEqual(gap_result.result["uxAccessibilityLane"]["status"], "conflict")
        self.assertEqual(derive_audit_exit_code(gap_result.result), gap_result.exit_code)

    def test_direct_callers_cannot_promote_local_figma_or_ux_evidence(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.canonical import sha256_digest
        from guardian_core.ux_evaluator import (
            REQUIRED_FLOW_AREAS,
            REQUIRED_SCREEN_AREAS,
            UX_EVALUATOR_CONTRACT_DIGEST,
        )

        figma = complete_adapter()
        figma["adapter"] = "figma"
        figma_result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=figma,
            resolutions=[],
            ux_checks=[],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        self.assertEqual(figma_result.result["designSystemLane"]["status"], "not_assessed")
        self.assertTrue(all(
            lane["status"] == "not_assessed"
            for lane in figma_result.result["coverage"]["categories"].values()
        ))

        source_digest = sha256_digest(sample_pin()["sourceCut"])
        trusted_checks = []
        for scope, digest, areas in (
            ("screen", "1" * 64, REQUIRED_SCREEN_AREAS),
            ("flow", "2" * 64, REQUIRED_FLOW_AREAS),
        ):
            for area in areas:
                trusted_checks.append({
                    "checkId": f"direct-{scope}-{area}",
                    "area": area,
                    "status": "allowed",
                    "message": "UX/accessibility evidence satisfied the required check.",
                    "evidence": {
                        "scope": scope,
                        "targetDigest": digest,
                        "evidenceDigest": "3" * 64,
                        "reasonCode": None,
                        "evaluatorDigest": UX_EVALUATOR_CONTRACT_DIGEST,
                        "sourceCutDigest": source_digest,
                    },
                })
        ux_result = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[],
            trusted_ux_checks=trusted_checks,
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        self.assertEqual(ux_result.result["uxAccessibilityLane"]["status"], "not_assessed")
        self.assertTrue(all(
            check["status"] == "not_assessed"
            for check in ux_result.result["uxAccessibilityLane"]["checks"]
        ))
if __name__ == "__main__":
    unittest.main()

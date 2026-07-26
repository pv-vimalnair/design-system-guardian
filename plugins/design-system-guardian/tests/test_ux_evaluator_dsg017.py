"""Deterministic UX/accessibility evaluator contract for DSG-017."""

from __future__ import annotations

import hashlib
import json
import unittest

from guardian_core.canonical import sha256_digest
from guardian_core.ux_evaluator import (
    REQUIRED_FLOW_AREAS,
    REQUIRED_SCREEN_AREAS,
    UX_EVALUATOR_CONTRACT_DIGEST,
    UxEvaluationIntegrityError,
    audit_checks_from_evaluation,
    evaluate_final_flow,
    evaluate_screen_checkpoint,
)


SCREEN_A = "a" * 64
SCREEN_B = "b" * 64
FLOW = "f" * 64
SOURCE_CUT = {
    "figmaFiles": [{"fileKey": "working-file", "version": "17"}],
    "catalogDigest": "c" * 64,
}


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _observation(
    *,
    target_digest: str,
    area: str,
    observed: object = True,
    expected: object = True,
    operator: str = "equals",
) -> dict[str, object]:
    return {
        "checkId": f"{target_digest[:8]}-{area}",
        "targetDigest": target_digest,
        "area": area,
        "operator": operator,
        "observed": observed,
        "expected": expected,
        "evidenceDigest": _digest(f"{target_digest}:{area}"),
    }


def _screen_observations(screen_digest: str) -> list[dict[str, object]]:
    return [
        _observation(target_digest=screen_digest, area=area)
        for area in REQUIRED_SCREEN_AREAS
    ]


def _flow_observations(flow_digest: str) -> list[dict[str, object]]:
    return [
        _observation(target_digest=flow_digest, area=area)
        for area in REQUIRED_FLOW_AREAS
    ]


class ScreenCheckpointEvaluationTest(unittest.TestCase):
    def test_complete_screen_checkpoint_is_allowed_but_never_authoritative(self) -> None:
        result = evaluate_screen_checkpoint(
            target={"screenDigest": SCREEN_A},
            observations=_screen_observations(SCREEN_A),
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["scope"], "screen_checkpoint")
        self.assertEqual(result["status"], "allowed")
        self.assertTrue(result["complete"])
        self.assertFalse(result["canAuthorizeProduction"])
        self.assertEqual(result["evaluatorDigest"], UX_EVALUATOR_CONTRACT_DIGEST)
        self.assertEqual(result["sourceCutDigest"], sha256_digest(SOURCE_CUT))
        self.assertEqual(result["targetDigest"], sha256_digest({"screenDigest": SCREEN_A}))
        self.assertEqual(result["reasonCodes"], [])
        self.assertTrue(all(item["status"] == "allowed" for item in result["checks"]))

    def test_missing_screen_area_is_not_assessed(self) -> None:
        observations = _screen_observations(SCREEN_A)
        missing_area = observations.pop()["area"]

        result = evaluate_screen_checkpoint(
            target={"screenDigest": SCREEN_A},
            observations=observations,
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["status"], "not_assessed")
        self.assertFalse(result["complete"])
        self.assertIn(
            {
                "reasonCode": "ux_screen_not_assessed",
                "count": 1,
            },
            result["reasonCodes"],
        )
        missing = [item for item in result["checks"] if item["area"] == missing_area]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["status"], "not_assessed")
        self.assertIsNone(missing[0]["evidenceDigest"])

    def test_complete_screen_gap_is_conflict_without_copying_private_evidence(self) -> None:
        observations = _screen_observations(SCREEN_A)
        observations[0] = _observation(
            target_digest=SCREEN_A,
            area=str(observations[0]["area"]),
            observed="private-company-copy",
            expected="approved",
        )

        result = evaluate_screen_checkpoint(
            target={"screenDigest": SCREEN_A},
            observations=observations,
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["status"], "conflict")
        self.assertTrue(result["complete"])
        self.assertEqual(
            result["reasonCodes"],
            [{"reasonCode": "ux_screen_gap", "count": 1}],
        )
        self.assertNotIn("private-company-copy", json.dumps(result, sort_keys=True))

    def test_caller_cannot_supply_a_pass_status(self) -> None:
        observation = _screen_observations(SCREEN_A)[0]
        observation["status"] = "allowed"

        with self.assertRaisesRegex(UxEvaluationIntegrityError, "unknown or missing fields"):
            evaluate_screen_checkpoint(
                target={"screenDigest": SCREEN_A},
                observations=[observation],
                    source_cut=SOURCE_CUT,
            )


class FinalFlowEvaluationTest(unittest.TestCase):
    def test_complete_final_flow_rechecks_every_screen_and_flow_area(self) -> None:
        observations = (
            _screen_observations(SCREEN_A)
            + _screen_observations(SCREEN_B)
            + _flow_observations(FLOW)
        )

        result = evaluate_final_flow(
            target={"flowDigest": FLOW, "screenDigests": [SCREEN_A, SCREEN_B]},
            observations=observations,
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["scope"], "final_flow")
        self.assertEqual(result["status"], "allowed")
        self.assertTrue(result["complete"])
        self.assertFalse(result["canAuthorizeProduction"])
        self.assertEqual(len(result["checks"]), len(observations))

    def test_incomplete_final_flow_reports_fixed_screen_and_flow_reasons(self) -> None:
        observations = _screen_observations(SCREEN_A)

        result = evaluate_final_flow(
            target={"flowDigest": FLOW, "screenDigests": [SCREEN_A, SCREEN_B]},
            observations=observations,
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["status"], "not_assessed")
        self.assertFalse(result["complete"])
        self.assertEqual(
            result["reasonCodes"],
            [
                {"reasonCode": "ux_flow_not_assessed", "count": len(REQUIRED_FLOW_AREAS)},
                {"reasonCode": "ux_screen_not_assessed", "count": len(REQUIRED_SCREEN_AREAS)},
            ],
        )

    def test_complete_flow_gap_is_conflict(self) -> None:
        observations = _screen_observations(SCREEN_A) + _flow_observations(FLOW)
        observations[-1] = _observation(
            target_digest=FLOW,
            area=str(observations[-1]["area"]),
            observed=0,
            expected=1,
            operator="at_least",
        )

        result = evaluate_final_flow(
            target={"flowDigest": FLOW, "screenDigests": [SCREEN_A]},
            observations=observations,
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result["status"], "conflict")
        self.assertEqual(
            result["reasonCodes"],
            [{"reasonCode": "ux_flow_gap", "count": 1}],
        )

    def test_duplicate_check_unknown_target_and_invalid_binding_are_rejected(self) -> None:
        duplicate = _screen_observations(SCREEN_A)[0]
        with self.assertRaisesRegex(UxEvaluationIntegrityError, "checkId values must be unique"):
            evaluate_final_flow(
                target={"flowDigest": FLOW, "screenDigests": [SCREEN_A]},
                observations=[duplicate, dict(duplicate)],
                    source_cut=SOURCE_CUT,
            )

        unknown = _observation(target_digest=SCREEN_B, area=REQUIRED_SCREEN_AREAS[0])
        with self.assertRaisesRegex(UxEvaluationIntegrityError, "outside the selected target"):
            evaluate_final_flow(
                target={"flowDigest": FLOW, "screenDigests": [SCREEN_A]},
                observations=[unknown],
                    source_cut=SOURCE_CUT,
            )

        with self.assertRaisesRegex(UxEvaluationIntegrityError, "sourceCut"):
            evaluate_screen_checkpoint(
                target={"screenDigest": SCREEN_A},
                observations=[],
                source_cut={},
            )


class AuditProjectionTest(unittest.TestCase):
    def test_mapper_validates_bindings_and_emits_existing_audit_check_shape(self) -> None:
        observations = _screen_observations(SCREEN_A)
        result = evaluate_screen_checkpoint(
            target={"screenDigest": SCREEN_A},
            observations=observations,
            source_cut=SOURCE_CUT,
        )
        reordered = evaluate_screen_checkpoint(
            target={"screenDigest": SCREEN_A},
            observations=list(reversed(observations)),
            source_cut=SOURCE_CUT,
        )

        self.assertEqual(result, reordered)
        self.assertRegex(UX_EVALUATOR_CONTRACT_DIGEST, r"^[0-9a-f]{64}$")
        checks = audit_checks_from_evaluation(
            result, target={"screenDigest": SCREEN_A}, source_cut=SOURCE_CUT
        )
        self.assertEqual(len(checks), len(REQUIRED_SCREEN_AREAS))
        self.assertEqual(
            set(checks[0]),
            {"checkId", "area", "status", "message", "evidence"},
        )
        self.assertTrue(all(item["status"] == "not_assessed" for item in checks))
        self.assertTrue(
            all(item["evidence"]["evidenceDigest"] is None for item in checks)
        )
        self.assertEqual(
            checks[0]["evidence"]["evaluatorDigest"],
            UX_EVALUATOR_CONTRACT_DIGEST,
        )
        self.assertEqual(
            checks[0]["evidence"]["sourceCutDigest"],
            sha256_digest(SOURCE_CUT),
        )
        self.assertFalse(result["canAuthorizeProduction"])

    def test_mapper_rejects_tampered_contract_status_and_source_binding(self) -> None:
        def clean_result() -> dict[str, object]:
            return evaluate_screen_checkpoint(
                target={"screenDigest": SCREEN_A},
                observations=_screen_observations(SCREEN_A),
                source_cut=SOURCE_CUT,
            )

        tampered_contract = clean_result()
        tampered_contract["evaluatorDigest"] = "0" * 64
        with self.assertRaisesRegex(UxEvaluationIntegrityError, "built-in evaluator contract"):
            audit_checks_from_evaluation(
                tampered_contract,
                target={"screenDigest": SCREEN_A},
                source_cut=SOURCE_CUT,
            )

        tampered_status = clean_result()
        tampered_status["status"] = "conflict"
        with self.assertRaisesRegex(UxEvaluationIntegrityError, "status differs"):
            audit_checks_from_evaluation(
                tampered_status,
                target={"screenDigest": SCREEN_A},
                source_cut=SOURCE_CUT,
            )

        incomplete_coverage = clean_result()
        incomplete_coverage["checks"].pop()
        with self.assertRaisesRegex(UxEvaluationIntegrityError, "required-area coverage"):
            audit_checks_from_evaluation(
                incomplete_coverage,
                target={"screenDigest": SCREEN_A},
                source_cut=SOURCE_CUT,
            )

        with self.assertRaisesRegex(UxEvaluationIntegrityError, "pinned source cut"):
            audit_checks_from_evaluation(
                clean_result(),
                target={"screenDigest": SCREEN_A},
                source_cut={**SOURCE_CUT, "catalogDigest": "d" * 64},
            )


if __name__ == "__main__":
    unittest.main()

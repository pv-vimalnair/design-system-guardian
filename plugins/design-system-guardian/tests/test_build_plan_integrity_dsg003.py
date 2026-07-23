import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_finalize_artifacts_dsg003 import COMPLETED_AT, STARTED_AT, attested_audit, provision_run
from tests.test_profile_snapshot import NOW


def plan_for(pin: dict, *, selections: list[dict] | None = None, sentinels: list[dict] | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "runId": pin["runId"],
        "profileId": pin["profileId"],
        "snapshotId": pin["snapshotId"],
        "policyDigest": pin["policyDigest"],
        "uxDecision": {
            "hierarchy": ["Primary action follows the approved hierarchy."],
            "states": ["Normal, loading, disabled, error, and success states were assessed."],
            "accessibility": ["Focus, semantics, contrast, and assistive behavior were assessed."],
            "componentIntent": ["Every approved component has a recorded product intent."],
        },
        "selections": selections or [],
        "sentinels": sentinels or [],
        "productionReady": not sentinels,
    }


class BuildPlanIntegrityTest(unittest.TestCase):
    def test_exact_authoritative_selection_bound_to_audit_can_be_sealed(self) -> None:
        from guardian_core.contracts import ExitCode
        from guardian_core.finalize import _finalize_run_at
        from guardian_core.resolver import _resolve_pinned_identity_at_home

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-build-plan")
            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                selection = _resolve_pinned_identity_at_home(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    request={
                        "kind": "token",
                        "identity": "color.action.primary",
                        "tokenType": "color",
                        "resolverContext": {"theme": "light"},
                    },
                )
            self.assertEqual(selection["status"], "allowed")
            audit, _ = attested_audit(home, pin, Path(directory), resolutions=[selection])
            plan = plan_for(pin, selections=[copy.deepcopy(selection)])

            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                result = _finalize_run_at(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    audit_result=audit,
                    build_plan=plan,
                    started_at=STARTED_AT,
                    completed_at=COMPLETED_AT,
                )
            self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
            self.assertFalse(result.production_ready)
            self.assertIn("build-plan", result.artifact_paths)

    def test_raw_or_unrecorded_selection_cannot_be_sealed(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at
        from guardian_core.resolver import _resolve_pinned_identity_at_home

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-build-forgery")
            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                selection = _resolve_pinned_identity_at_home(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    request={"kind": "token", "identity": "color.action.primary"},
                )
            audit, _ = attested_audit(home, pin, Path(directory), resolutions=[selection])

            raw = copy.deepcopy(selection)
            raw["request"]["rawValue"] = "#0055FF"
            cases = {
                "raw request": plan_for(pin, selections=[raw]),
                "omitted audit selection": plan_for(pin),
            }
            for label, forged in cases.items():
                with self.subTest(label=label), patch("guardian_core.resolver._utc_now", return_value=NOW):
                    with self.assertRaises(FinalizationError):
                        _finalize_run_at(
                            home,
                            profile_id=pin["profileId"],
                            run_id=pin["runId"],
                            audit_result=audit,
                            build_plan=forged,
                            started_at=STARTED_AT,
                            completed_at=COMPLETED_AT,
                        )

    def test_ux_record_and_sentinel_set_must_match_the_canonical_contract(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at
        from guardian_core.sentinels import make_sentinel

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-build-sentinel")
            audit, _ = attested_audit(home, pin, Path(directory))
            empty_ux = plan_for(pin)
            empty_ux["uxDecision"]["accessibility"] = []
            unrecorded_sentinel = plan_for(
                pin,
                sentinels=[
                    make_sentinel(
                        kind="icon",
                        request_id="unrecorded-icon",
                        policy_digest=pin["policyDigest"],
                    )
                ],
            )
            for label, forged in {
                "empty UX lane": empty_ux,
                "unrecorded sentinel": unrecorded_sentinel,
            }.items():
                with self.subTest(label=label), self.assertRaises(FinalizationError):
                    _finalize_run_at(
                        home,
                        profile_id=pin["profileId"],
                        run_id=pin["runId"],
                        audit_result=audit,
                        build_plan=forged,
                        started_at=STARTED_AT,
                        completed_at=COMPLETED_AT,
                    )


if __name__ == "__main__":
    unittest.main()

import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
)
from tests.test_audit_dsg003 import allowed_ux_check, complete_adapter, sample_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


STARTED_AT = "2026-07-15T12:00:00Z"
COMPLETED_AT = "2026-07-15T12:00:01Z"


def provision_run(
    home: Path,
    *,
    run_id: str = "run-finalize-1",
    project_root: Path | None = None,
) -> dict:
    from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor
    from guardian_core.preflight import preflight_snapshot
    from guardian_core.profile import install_profile
    from guardian_core.snapshot import ingest_snapshot
    if project_root is None:
        from tests.flutter_runner_test_support import create_minimal_flutter_project

        project_root = create_minimal_flutter_project(home, name=f"flutter-{run_id}")

    public_key = home / "catalog-authority-input.pem"
    public_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    install_policy_anchor(home, catalog_authority_public_key=public_key)
    profile = sample_profile()
    install_profile(home, profile)
    catalog_source = sample_catalog()
    for assets in catalog_source["registry"].values():
        for asset in assets:
            asset["codeMappings"] = []
    catalog = attest_catalog(catalog_source, profile, sequence=1, issued_at=NOW)
    with patch("guardian_core.snapshot._utc_now", return_value=NOW):
        ingest_snapshot(home, profile, catalog)
    with patch("guardian_core.preflight._utc_now", return_value=NOW):
        return preflight_snapshot(
            home,
            profile_id="example-company",
            run_id=run_id,
            policy_digest=EXPECTED_POLICY_SHA256,
            project_root=project_root,
        )["pin"]


def clean_audit(pin: dict):
    from guardian_core.audit import evaluate_audit

    adapter = complete_adapter()
    adapter["sourceCut"] = copy.deepcopy(pin["sourceCut"])
    from tests.test_flutter_adapter_normalization_dsg003 import flutter_config

    adapter["configDigest"] = flutter_config(pin)["configDigest"]
    timestamp = NOW.isoformat().replace("+00:00", "Z")
    snapshot = sample_snapshot()
    snapshot.update(
        {
            "snapshotId": pin["snapshotId"],
            "sourceCut": copy.deepcopy(pin["sourceCut"]),
            "createdAt": timestamp,
            "refreshAttemptedAt": timestamp,
            "lastSuccessfulRefreshAt": timestamp,
            "sourceEvidence": {"refreshAttempted": True},
        }
    )
    project_evidence = {
        **copy.deepcopy(pin["projectBinding"]),
        "assessedTreeDigest": "a" * 64,
        "analysisInputsDigest": "b" * 64,
    }
    with patch("guardian_core.audit._utc_now", return_value=NOW):
        return evaluate_audit(
            run_pin=pin,
            adapter_result=adapter,
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=project_evidence,
            verified_snapshot=snapshot,
        )


def attested_audit(
    home: Path,
    pin: dict,
    root: Path,
    *,
    resolutions: list[dict] | None = None,
) -> tuple[dict, Path]:
    from tests.flutter_runner_test_support import runner_side_effect
    from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical

    project = Path(pin["projectBinding"]["canonicalRoot"])
    request_path = root / f"audit-{pin['runId']}.json"
    write_canonical(
        request_path,
        {
            "schemaVersion": 1,
            "projectRoot": str(project),
            "resolutions": resolutions or [],
            "uxChecks": [allowed_ux_check()],
        },
    )
    with patch(
        "guardian_core.cli.run_flutter_analysis",
        side_effect=runner_side_effect(),
    ):
        code, audit = invoke(
            home,
            [
                "audit", "--profile", pin["profileId"], "--run-id", pin["runId"],
                "--input", str(request_path),
            ],
        )
    if code != 4:
        raise AssertionError(f"Expected fail-closed UX audit exit 4, received {code}: {audit}")
    return audit, project


class SealedRunArtifactTest(unittest.TestCase):
    def test_sealed_artifact_is_canonical_tamper_evident_and_idempotent(self) -> None:
        from guardian_core.canonical import canonical_json_bytes
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.run_artifacts import (
            RunArtifactIntegrityError,
            seal_run_artifact,
            verify_run_artifact,
            write_run_artifact,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_run(home)
            payload = {
                "schemaVersion": 1,
                "runId": "run-finalize-1",
                "profileId": "example-company",
                "policyDigest": EXPECTED_POLICY_SHA256,
                "value": {"b": 2, "a": 1},
            }
            envelope = seal_run_artifact(
                home,
                artifact_type="coverage",
                profile_id="example-company",
                run_id="run-finalize-1",
                payload=payload,
            )
            path = write_run_artifact(home, envelope)
            same_path = write_run_artifact(home, envelope)

            self.assertEqual(path, same_path)
            self.assertEqual(path.read_bytes(), canonical_json_bytes(envelope))
            self.assertEqual(verify_run_artifact(home, envelope), payload)
            self.assertNotIn("key", str(envelope).lower())

            tampered = copy.deepcopy(envelope)
            tampered["payload"]["value"]["a"] = 9
            with self.assertRaises(RunArtifactIntegrityError):
                verify_run_artifact(home, tampered)

    def test_readable_report_is_derived_only_from_verified_audit_evidence(self) -> None:
        from guardian_core.run_artifacts import (
            RunArtifactIntegrityError,
            render_audit_report,
            seal_run_artifact,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home)
            audit = clean_audit(pin).result
            envelope = seal_run_artifact(
                home,
                artifact_type="audit-result",
                profile_id="example-company",
                run_id="run-finalize-1",
                payload=audit,
            )
            first = render_audit_report(home, envelope)
            second = render_audit_report(home, copy.deepcopy(envelope))
            self.assertEqual(first, second)
            self.assertIn("Design-system compliance: allowed", first)
            self.assertIn("UX/accessibility: not_assessed", first)
            for category in complete_adapter()["categories"]:
                self.assertIn(category, first)

            tampered = copy.deepcopy(envelope)
            tampered["payload"]["productionReady"] = True
            with self.assertRaises(RunArtifactIntegrityError):
                render_audit_report(home, tampered)


class FinalizationTest(unittest.TestCase):
    def test_public_finalize_uses_trusted_clock_and_has_no_time_parameter(self) -> None:
        from guardian_core.finalize import finalize_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-trusted-time")
            audit, _ = attested_audit(home, pin, Path(directory))
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                result = finalize_run(
                    home,
                    profile_id="example-company",
                    run_id="run-trusted-time",
                    audit_result=audit,
                    build_plan=None,
                )
            expected = NOW.isoformat().replace("+00:00", "Z")
            self.assertEqual(result.manifest["startedAt"], expected)
            self.assertEqual(result.manifest["completedAt"], expected)
            with self.assertRaises(TypeError):
                finalize_run(
                    home,
                    profile_id="example-company",
                    run_id="run-trusted-time",
                    audit_result=audit,
                    build_plan=None,
                    completed_at="2099-01-01T00:00:00Z",
                )

    def test_finalize_revalidates_derived_summaries_and_lanes_before_sealing(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at as finalize_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-deep-revalidate")
            baseline = clean_audit(pin).result

            cases = []
            summary = copy.deepcopy(baseline)
            summary["designSystemLane"]["resolutionSummary"]["allowed"] = 1
            cases.append(("resolution-summary", summary))

            diagnostic = copy.deepcopy(baseline)
            diagnostic["designSystemLane"]["status"] = "conflict"
            diagnostic["designSystemLane"]["violations"] = [{
                "diagnosticId": "wrong-lane", "category": "colors",
                "kind": "design_system_gap", "message": "Wrong lane.",
                "evidence": {"approvedIdentity": "color.text", "requiredAction": "request_design_system_change"},
            }]
            cases.append(("diagnostic-lane", diagnostic))

            ux = copy.deepcopy(baseline)
            ux["uxAccessibilityLane"]["status"] = "conflict"
            cases.append(("ux-summary", ux))

            totals = copy.deepcopy(baseline)
            totals["coverage"]["assessedFiles"] = 2
            cases.append(("adapter-totals", totals))

            for label, audit in cases:
                with self.subTest(label=label):
                    with self.assertRaises(FinalizationError):
                        finalize_run(
                            home, profile_id="example-company", run_id="run-deep-revalidate",
                            audit_result=audit, build_plan=None,
                            started_at=STARTED_AT, completed_at=COMPLETED_AT,
                        )

    def test_finalize_reassesses_pinned_snapshot_and_blocks_seven_day_staleness(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.contracts import ExitCode
        from guardian_core.finalize import _finalize_run_at as finalize_run
        from guardian_core.run_artifacts import verify_run_artifact
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-stale-final")
            audit, _ = attested_audit(home, pin, Path(directory))
            result = finalize_run(home, profile_id="example-company", run_id="run-stale-final", audit_result=audit, build_plan=None, started_at="2026-07-15T12:00:00Z", completed_at="2026-07-23T12:00:00Z")
            self.assertEqual(result.exit_code, ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)
            self.assertFalse(result.production_ready)
            sealed = read_canonical_json(result.artifact_paths["audit-result"])
            self.assertEqual(verify_run_artifact(home, sealed)["designSystemLane"]["status"], "stale")

    def test_finalize_rejects_cross_profile_resolution_evidence_before_sealing(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at as finalize_run
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-cross-profile")
            audit = clean_audit(pin).result
            audit["resolutions"] = [{"schemaVersion": 1, "status": "allowed", "profileId": "other-company", "snapshotId": pin["snapshotId"], "request": {"kind": "icon", "identity": "icon.check"}, "selectedIdentity": "icon.check", "evidence": {}, "sentinel": None}]
            audit["designSystemLane"]["resolutionSummary"]["allowed"] = 1
            with self.assertRaises(FinalizationError):
                finalize_run(home, profile_id="example-company", run_id="run-cross-profile", audit_result=audit, build_plan=None, started_at=STARTED_AT, completed_at=COMPLETED_AT)

    def test_finalize_writes_sealed_evidence_manifest_and_derived_report(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.contracts import ExitCode
        from guardian_core.finalize import _finalize_run_at as finalize_run
        from guardian_core.run_artifacts import verify_run_artifact

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home)
            audit, _ = attested_audit(home, pin, Path(directory))
            result = finalize_run(
                home,
                profile_id="example-company",
                run_id="run-finalize-1",
                audit_result=audit,
                build_plan=None,
                started_at=STARTED_AT,
                completed_at=COMPLETED_AT,
            )
            repeated = finalize_run(
                home,
                profile_id="example-company",
                run_id="run-finalize-1",
                audit_result=copy.deepcopy(audit),
                build_plan=None,
                started_at=STARTED_AT,
                completed_at=COMPLETED_AT,
            )

            self.assertEqual(result, repeated)
            self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
            self.assertFalse(result.production_ready)
            self.assertEqual(
                set(result.artifact_paths),
                {"audit-result", "coverage", "run-manifest", "readable-report"},
            )
            for kind in ("audit-result", "coverage", "run-manifest"):
                envelope = read_canonical_json(result.artifact_paths[kind])
                verify_run_artifact(home, envelope)
            report = result.artifact_paths["readable-report"].read_text(encoding="utf-8")
            self.assertIn("Production ready: no", report)
            self.assertEqual(result.manifest["sourceCut"], pin["sourceCut"])

    def test_finalize_rejects_post_audit_claimed_pass_for_missing_sentinel(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at as finalize_run
        from guardian_core.resolver import _resolve_pinned_identity_at_home

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root
            pin = provision_run(home)
            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                missing = _resolve_pinned_identity_at_home(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    request={
                        "requestId": "req-missing",
                        "kind": "token",
                        "identity": "token.none",
                    },
                )
            self.assertEqual(missing["status"], "missing")
            audit, _ = attested_audit(home, pin, root, resolutions=[missing])
            audit["productionReady"] = True

            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                with self.assertRaisesRegex(FinalizationError, "attestation"):
                    finalize_run(
                        home,
                        profile_id="example-company",
                        run_id="run-finalize-1",
                        audit_result=audit,
                        build_plan=None,
                        started_at=STARTED_AT,
                        completed_at=COMPLETED_AT,
                    )

    def test_finalize_refuses_audit_not_bound_to_pinned_source_cut(self) -> None:
        from guardian_core.contracts import ExitCode
        from guardian_core.finalize import FinalizationError, _finalize_run_at as finalize_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home)
            audit = clean_audit(pin).result
            audit["designSystemLane"]["sourceCutDigest"] = "0" * 64
            with self.assertRaises(FinalizationError) as raised:
                finalize_run(
                    home,
                    profile_id="example-company",
                    run_id="run-finalize-1",
                    audit_result=audit,
                    build_plan=None,
                    started_at=STARTED_AT,
                    completed_at=COMPLETED_AT,
                )
            self.assertEqual(
                raised.exception.exit_code,
                ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY,
            )


if __name__ == "__main__":
    unittest.main()

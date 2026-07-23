import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.flutter_runner_test_support import create_minimal_flutter_project, runner_side_effect
from tests.test_audit_dsg003 import allowed_ux_check
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_finalize_artifacts_dsg003 import provision_run
from tests.test_profile_snapshot import NOW


class ProjectBindingTest(unittest.TestCase):
    def test_preflight_binds_intended_project_and_audit_rejects_decoy(self) -> None:
        from guardian_core.preflight import preflight_snapshot

        self.assertIn("project_root", inspect.signature(preflight_snapshot).parameters)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            intended = create_minimal_flutter_project(root, name="intended-product")
            decoy = create_minimal_flutter_project(root, name="clean-decoy")
            pin = provision_run(
                home,
                run_id="run-project-decoy",
                project_root=intended,
            )

            self.assertEqual(pin["projectBinding"]["canonicalRoot"], str(intended))
            self.assertRegex(pin["projectBinding"]["rootIdentity"], r"^[0-9a-f]{64}$")
            request_path = root / "audit-decoy.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 1,
                    "projectRoot": str(decoy),
                    "resolutions": [],
                    "uxChecks": [allowed_ux_check()],
                },
            )
            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=AssertionError("decoy must be rejected before analysis"),
            ):
                code, error = invoke(
                    home,
                    [
                        "audit",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-project-decoy",
                        "--input",
                        str(request_path),
                    ],
                )

            self.assertEqual(code, 2)
            self.assertIn("intended project", error["message"].lower())

    def test_project_evidence_is_visible_in_audit_manifest_and_report(self) -> None:
        from guardian_core.finalize import _finalize_run_at

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            project = create_minimal_flutter_project(root, name="visible-product")
            git_commit = "a" * 40
            (project / ".git").mkdir()
            (project / ".git" / "HEAD").write_text(
                git_commit + "\n",
                encoding="ascii",
                newline="\n",
            )
            pin = provision_run(
                home,
                run_id="run-project-visible",
                project_root=project,
            )
            request_path = root / "audit-visible.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 1,
                    "projectRoot": str(project),
                    "resolutions": [],
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
                        "audit",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-project-visible",
                        "--input",
                        str(request_path),
                    ],
                )
            self.assertEqual(code, 4)
            evidence = audit["projectEvidence"]
            self.assertEqual(evidence["canonicalRoot"], str(project))
            self.assertEqual(evidence["rootIdentity"], pin["projectBinding"]["rootIdentity"])
            self.assertEqual(evidence["gitCommit"], git_commit)
            self.assertRegex(evidence["assessedTreeDigest"], r"^[0-9a-f]{64}$")
            self.assertRegex(evidence["analysisInputsDigest"], r"^[0-9a-f]{64}$")

            result = _finalize_run_at(
                home,
                profile_id="example-company",
                run_id="run-project-visible",
                audit_result=audit,
                build_plan=None,
                started_at=NOW.isoformat().replace("+00:00", "Z"),
                completed_at=NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(result.manifest["projectEvidence"], evidence)
            report = result.artifact_paths["readable-report"].read_text(encoding="utf-8")
            self.assertIn(f"Intended project: {project}", report)
            self.assertIn(f"Project root identity: {evidence['rootIdentity']}", report)
            self.assertIn(f"Assessed tree: {evidence['assessedTreeDigest']}", report)
            self.assertIn(f"Analysis inputs: {evidence['analysisInputsDigest']}", report)
            self.assertIn(f"Git commit (local observation): {git_commit}", report)


if __name__ == "__main__":
    unittest.main()

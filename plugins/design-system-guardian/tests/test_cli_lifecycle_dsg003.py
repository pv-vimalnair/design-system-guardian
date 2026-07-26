import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.flutter_runner_test_support import (
    prepare_contract_runner_dependencies,
    runner_side_effect,
)
from tests.test_audit_dsg003 import allowed_ux_check
from tests.test_finalize_artifacts_dsg003 import provision_run
from tests.test_migrations_dsg003 import provision as provision_migration
from tests.test_profile_snapshot import NOW


def write_canonical(path: Path, value: dict) -> None:
    from guardian_core.canonical import atomic_write_json

    atomic_write_json(path, value)


def invoke(home: Path, argv: list[str]) -> tuple[int, dict]:
    from guardian_core.cli import main

    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch("guardian_core.cli.default_guardian_home", return_value=home),
        patch("guardian_core.audit._utc_now", return_value=NOW),
        patch("guardian_core.resolver._utc_now", return_value=NOW),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        code = main(argv)
    stream = stdout.getvalue() if stdout.getvalue() else stderr.getvalue()
    return code, json.loads(stream)


def audit_request(pin: dict, project: Path) -> dict:
    return {
        "schemaVersion": 1,
        "projectRoot": str(project),
        "resolutions": [],
        "uxChecks": [allowed_ux_check()],
    }


def file_state(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


class LifecycleCliTest(unittest.TestCase):
    def test_audit_is_product_read_only_and_finalize_verifies_sealed_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_run(home, run_id="run-cli-clean")
            project = Path(pin["projectBinding"]["canonicalRoot"])
            prepare_contract_runner_dependencies(project)
            request_path = root / "audit-request.json"
            write_canonical(request_path, audit_request(pin, project))
            before = file_state(project)

            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=runner_side_effect(),
            ):
                code, audit = invoke(home, [
                    "audit",
                    "--profile",
                    "example-company",
                    "--run-id",
                    "run-cli-clean",
                    "--input",
                    str(request_path),
                ])

            self.assertEqual(code, 4)
            self.assertFalse(audit["productionReady"])
            self.assertEqual(audit["uxAccessibilityLane"]["status"], "not_assessed")
            self.assertEqual(file_state(project), before)
            from guardian_core.run_artifacts import read_run_artifact

            attestation = read_run_artifact(
                home,
                profile_id="example-company",
                run_id="run-cli-clean",
                artifact_type="analysis-attestation",
            )
            self.assertEqual(attestation["payload"]["auditResultDigest"], __import__("guardian_core.canonical", fromlist=["sha256_digest"]).sha256_digest(audit))

            audit_path = root / "audit-result.json"
            write_canonical(audit_path, audit)
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                code, finalized = invoke(
                    home,
                    [
                        "finalize",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-cli-clean",
                        "--audit-result",
                        str(audit_path),
                    ],
                )

            self.assertEqual(code, 4)
            self.assertFalse(finalized["productionReady"])
            self.assertFalse(finalized["postRunAssessment"]["sourceMutationPerformed"])
            self.assertEqual(
                set(finalized["artifactPaths"]),
                {"audit-result", "coverage", "run-manifest", "post-run-assessment", "readable-report"},
            )
            for relative in finalized["artifactPaths"].values():
                self.assertTrue((home / relative).is_file())

            before_self_check = file_state(home)
            code, assessment = invoke(
                home,
                [
                    "self-check",
                    "--profile",
                    "example-company",
                    "--run-id",
                    "run-cli-clean",
                ],
            )
            self.assertEqual(code, 4)
            self.assertEqual(assessment, finalized["postRunAssessment"])
            self.assertEqual(file_state(home), before_self_check)

            (project / "lib" / "main.dart").write_text(
                "void main() { print('changed'); }\n", encoding="utf-8", newline="\n"
            )
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                code, error = invoke(
                    home,
                    [
                        "finalize", "--profile", "example-company", "--run-id", "run-cli-clean",
                        "--audit-result", str(audit_path),
                    ],
                )
            self.assertEqual(code, 2)
            self.assertIn("source manifest changed", error["message"].lower())

    def test_audit_maps_trusted_runner_and_adversarial_inputs_to_fail_closed_codes(self) -> None:
        def violation(raw: dict) -> None:
            raw["productionReady"] = False
            raw["coverage"]["colors"]["diagnosticCount"] = 1
            raw["diagnostics"] = [
                {
                    "severity": "ERROR",
                    "code": "guardian_unapproved_color",
                    "path": "lib/main.dart",
                    "line": 12,
                    "column": 8,
                    "length": 10,
                    "message": "Unapproved color.",
                }
            ]

        def unsupported(raw: dict) -> None:
            raw["status"] = "unsupported"
            raw["productionReady"] = False
            raw["coverage"]["motion"]["status"] = "unsupported"

        cases = (
            ("violation", 1, violation, "clean"),
            ("caller-source-claim", 2, None, "source"),
            ("unsupported", 4, unsupported, "clean"),
            ("cross-profile", 2, None, "cross-profile"),
        )
        for label, expected, mutator, resolution_case in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home = root / "guardian-home"
                home.mkdir()
                pin = provision_run(home, run_id=f"run-cli-{label}")
                project = Path(pin["projectBinding"]["canonicalRoot"])
                request = audit_request(pin, project)
                if resolution_case == "source":
                    request["resolutions"] = [{
                        "schemaVersion": 1, "status": "source_unavailable",
                        "profileId": "example-company", "snapshotId": pin["snapshotId"],
                        "request": {"kind": "icon", "identity": "icon.check"},
                        "selectedIdentity": None,
                        "evidence": {"reason": "source_fetch_failed"}, "sentinel": None,
                    }]
                elif resolution_case == "cross-profile":
                    request["resolutions"] = [{
                        "schemaVersion": 1, "status": "allowed",
                        "profileId": "other-company", "snapshotId": pin["snapshotId"],
                        "request": {"kind": "icon", "identity": "icon.check"},
                        "selectedIdentity": "icon.check",
                        "evidence": {"policyDigest": pin["policyDigest"]}, "sentinel": None,
                    }]
                request_path = root / "audit-request.json"
                write_canonical(request_path, request)
                with patch(
                    "guardian_core.cli.run_flutter_analysis",
                    side_effect=runner_side_effect(mutator),
                ):
                    write_canonical(request_path, request)
                    code, _ = invoke(
                        home,
                        [
                            "audit",
                            "--profile",
                            "example-company",
                            "--run-id",
                            f"run-cli-{label}",
                            "--input",
                            str(request_path),
                        ],
                    )
                self.assertEqual(code, expected)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_run(home, run_id="run-cli-noncanonical")
            project = Path(pin["projectBinding"]["canonicalRoot"])
            request_path = root / "audit-request.json"
            request_path.write_text(json.dumps(audit_request(pin, project), indent=2), encoding="utf-8")
            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=runner_side_effect(),
            ):
                code, _ = invoke(home, [
                    "audit",
                    "--profile",
                    "example-company",
                    "--run-id",
                    "run-cli-noncanonical",
                    "--input",
                    str(request_path),
                ])
            self.assertEqual(code, 2)

    def test_migrate_uses_profile_containment_and_refuses_future_schema(self) -> None:
        from guardian_core.canonical import atomic_write_json

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            artifact, digest = provision_migration(home)

            code, result = invoke(
                home,
                [
                    "migrate",
                    "--profile",
                    "example-company",
                    "--artifact",
                    "runtime-state.json",
                ],
            )
            self.assertEqual(code, 0)
            self.assertFalse(result["changed"])
            self.assertEqual(result["currentVersion"], 1)

            atomic_write_json(
                artifact,
                {"schemaVersion": 9, "policyDigest": digest, "value": "future"},
            )
            before = artifact.read_bytes()
            code, _ = invoke(
                home,
                [
                    "migrate",
                    "--profile",
                    "example-company",
                    "--artifact",
                    "runtime-state.json",
                ],
            )
            self.assertEqual(code, 2)
            self.assertEqual(artifact.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

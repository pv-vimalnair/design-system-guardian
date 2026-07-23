from __future__ import annotations

import copy
import hashlib
import inspect
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[3]

import sys

sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from guardian_core.flutter_runner import (
    ATTESTATION_PREFIX,
    FlutterRunnerIntegrityError,
    FlutterRunnerUnsupportedError,
    enumerate_relevant_dart_files,
    run_flutter_analysis,
    verify_flutter_project_evidence,
)
from tests.flutter_authority_test_support import (
    create_test_dart_sdk,
    create_test_package,
    package_binding,
)


class FlutterTrustedRunnerTests(unittest.TestCase):
    def make_project(self, root: Path) -> Path:
        project = root / "product"
        (project / "lib" / "nested").mkdir(parents=True)
        (project / "build").mkdir()
        (project / ".dart_tool").mkdir()
        (project / "pubspec.yaml").write_text(
            "name: guarded_product\nenvironment:\n  sdk: ^3.10.0\n",
            encoding="utf-8",
        )
        (project / "analysis_options.yaml").write_text(
            "analyzer:\n  exclude:\n    - build/**\n",
            encoding="utf-8",
        )
        (project / "lib" / "main.dart").write_text(
            "void main() {}\n// ignore: guardian_unapproved_icon\n",
            encoding="utf-8",
        )
        (project / "lib" / "nested" / "card.dart").write_text(
            "class Card {}\n",
            encoding="utf-8",
        )
        (project / "build" / "ignored.dart").write_text("bad()\n", encoding="utf-8")
        flutter_root = create_test_package(
            root / "flutter-package", name="flutter", marker="framework"
        )
        (project / ".dart_tool" / "package_config.json").write_bytes(
            canonical_json_bytes(
                {
                    "configVersion": 2,
                    "packages": [
                        {"name": "guarded_product", "rootUri": "../", "packageUri": "lib/"},
                        {
                            "name": "flutter",
                            "rootUri": flutter_root.resolve().as_uri() + "/",
                            "packageUri": "lib/",
                        },
                    ],
                }
            )
        )
        return project

    def make_config(self, root: Path) -> tuple[Path, dict, dict, Path]:
        executable, toolchain = create_test_dart_sdk(root / "host" / "dart-sdk")
        flutter_root = root / "flutter-package"
        config = {
            "schemaVersion": 1,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "profileId": "example-company",
            "policyDigest": "a" * 64,
            "snapshotId": "b" * 64,
            "sourceCutDigest": sha256_digest({"figma": "v1"}),
            "toolchain": toolchain,
            "requiredPackages": {"flutter": package_binding(flutter_root)},
            "approvedPackages": {},
            "approvedIdentities": {
                "colors": [],
                "textStyles": [],
                "icons": [],
                "dimensions": [],
                "effects": [],
                "motion": [],
                "widgets": [],
            },
            "componentVariants": {},
        }
        config["configDigest"] = sha256_digest(config)
        path = root / "host" / "flutter-adapter.json"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(canonical_json_bytes(config))
        run_pin = {
            "schemaVersion": 1,
            "runId": "run-001",
            "profileId": config["profileId"],
            "snapshotId": config["snapshotId"],
            "policyDigest": config["policyDigest"],
            "sourceCut": {"figma": "v1"},
        }
        return path, config, run_pin, executable

    @staticmethod
    def tree_digest(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def execute(
        self,
        root: Path,
        *,
        attestation_mode: str = "exact",
        extra: str = "",
        analyzer_exit_code: int = 1,
    ) -> dict:
        project = self.make_project(root)
        config_path, config, run_pin, executable = self.make_config(root)
        before = self.tree_digest(project)

        def which(name: str) -> str | None:
            if name == "flutter":
                return None
            if name == "dart":
                return str(executable)
            if name == "git":
                return None
            return None

        def invoke(command, **kwargs):
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, "Dart SDK version: 3.10.0", "")
            stage = Path(kwargs["cwd"])
            self.assertNotEqual(stage.resolve(), project.resolve())
            options = (stage / "analysis_options.yaml").read_text(encoding="utf-8")
            self.assertIn("design_system_guardian_flutter:", options)
            self.assertIn("path:", options)
            sentinel_path = Path(kwargs["env"]["DESIGN_SYSTEM_GUARDIAN_SENTINEL_EVIDENCE"])
            sentinels = json.loads(sentinel_path.read_text(encoding="utf-8"))
            self.assertEqual(sentinels["configDigest"], config["configDigest"])
            lines = []
            for relative in ("lib/main.dart", "lib/nested/card.dart"):
                digest = config["configDigest"]
                if attestation_mode == "mismatch" and relative == "lib/main.dart":
                    digest = "f" * 64
                if attestation_mode == "missing" and relative == "lib/main.dart":
                    continue
                line = (
                    "WARNING|STATIC_WARNING|"
                    "design_system_guardian_flutter/guardian_compilation_unit_attestation|"
                    f"{stage / Path(relative)}|1|1|1|{ATTESTATION_PREFIX}{digest}"
                )
                lines.append(line)
                if attestation_mode == "duplicate" and relative == "lib/main.dart":
                    lines.append(line)
            if extra:
                lines.append(extra.replace("{stage}", str(stage)))
            return subprocess.CompletedProcess(
                command,
                analyzer_exit_code,
                "\n".join(lines) + "\n",
                "",
            )

        with mock.patch("guardian_core.flutter_runner.shutil.which", side_effect=which), mock.patch(
            "guardian_core.flutter_runner.subprocess.run", side_effect=invoke
        ):
            result = run_flutter_analysis(
                project_root=project,
                adapter_config_path=config_path,
                run_pin=run_pin,
                expected_sentinels=(
                    {"requestId": "DS-42", "kind": "icon", "policyDigest": "a" * 64},
                ),
            )
        self.assertEqual(before, self.tree_digest(project), "audit runner wrote into product tree")
        return result

    def test_enumeration_hashes_every_relevant_unit_and_rejects_hidden_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = self.make_project(Path(directory))
            files = enumerate_relevant_dart_files(project)
            self.assertEqual([item["path"] for item in files], ["lib/main.dart", "lib/nested/card.dart"])
            self.assertTrue(all(len(item["sha256"]) == 64 for item in files))
            if hasattr(Path, "symlink_to"):
                try:
                    (project / "lib" / "escape.dart").symlink_to(project / "lib" / "main.dart")
                except OSError:
                    return
                with self.assertRaisesRegex(FlutterRunnerIntegrityError, "link|reparse"):
                    enumerate_relevant_dart_files(project)

    def test_host_runner_derives_result_and_strips_verified_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.execute(Path(directory))
        self.assertEqual([item["path"] for item in evidence["project"]["files"]], ["lib/main.dart", "lib/nested/card.dart"])
        self.assertEqual(evidence["project"]["assessedTreeDigest"], sha256_digest(evidence["project"]["files"]))
        self.assertEqual(evidence["project"]["gitCommit"], None)
        self.assertTrue(Path(evidence["project"]["canonicalRoot"]).is_absolute())
        self.assertEqual(
            [item["path"] for item in evidence["project"]["analysisInputs"]],
            [".dart_tool/package_config.json", "analysis_options.yaml", "pubspec.yaml"],
        )
        self.assertEqual(evidence["analyzer"]["tool"], "dart")
        self.assertTrue(Path(evidence["analyzer"]["executablePath"]).is_absolute())
        self.assertEqual(len(evidence["analyzer"]["executableSha256"]), 64)
        result = evidence["adapterResult"]
        self.assertEqual(result["analysis"], {"method": "dart_analyzer_ast", "complete": True, "assessedFiles": 2, "totalFiles": 2})
        self.assertEqual(result["diagnostics"], [])
        self.assertEqual(len(result["suppressionScan"]["findings"]), 1)
        self.assertFalse(result["productionReady"])

    def test_missing_duplicate_or_mismatched_unit_attestation_fails_closed(self) -> None:
        for mode in ("missing", "duplicate", "mismatch"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(FlutterRunnerIntegrityError, "attestation"):
                    self.execute(Path(directory), attestation_mode=mode)

    def test_non_guardian_analyzer_error_makes_coverage_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            extra = "ERROR|COMPILE_TIME_ERROR|UNDEFINED_IDENTIFIER|{stage}/lib/main.dart|1|1|3|Undefined name"
            with self.assertRaisesRegex(FlutterRunnerIntegrityError, "non-Guardian analyzer error"):
                self.execute(Path(directory), extra=extra)

    def test_visual_primitive_diagnostic_is_a_component_violation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            extra = "WARNING|STATIC_WARNING|design_system_guardian_flutter/guardian_unapproved_visual_primitive|{stage}/lib/main.dart|1|1|3|Raw visual primitive"
            evidence = self.execute(Path(directory), extra=extra)
        result = evidence["adapterResult"]
        self.assertEqual(
            [item["code"] for item in result["diagnostics"]],
            ["guardian_unapproved_visual_primitive"],
        )
        self.assertEqual(result["coverage"]["components"]["diagnosticCount"], 1)

    def test_analyzer_exit_code_outside_documented_range_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FlutterRunnerIntegrityError, "exit code"):
                self.execute(Path(directory), analyzer_exit_code=4)

    def test_git_observation_never_executes_a_path_selected_binary(self) -> None:
        from guardian_core.flutter_runner import _git_commit

        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "guardian_core.flutter_runner.shutil.which", side_effect=AssertionError("PATH Git executed")
        ):
            self.assertIsNone(_git_commit(Path(directory)))

    def test_finalizer_verifier_rejects_source_change_and_cross_root_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self.execute(root)
            verified = verify_flutter_project_evidence(evidence)
            self.assertEqual(verified, evidence["project"])
            (root / "product" / "lib" / "main.dart").write_text("void changed() {}\n", encoding="utf-8")
            with self.assertRaisesRegex(FlutterRunnerIntegrityError, "manifest|changed"):
                verify_flutter_project_evidence(evidence)

    def test_absent_runtime_is_unsupported_and_executable_is_not_caller_selectable(self) -> None:
        self.assertNotIn("executable", inspect.signature(run_flutter_analysis).parameters)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self.make_project(root)
            config_path, _, run_pin, _ = self.make_config(root)
            with mock.patch("guardian_core.flutter_runner.shutil.which", return_value=None):
                with self.assertRaises(FlutterRunnerUnsupportedError) as raised:
                    run_flutter_analysis(
                        project_root=project,
                        adapter_config_path=config_path,
                        run_pin=run_pin,
                    )
            self.assertEqual(raised.exception.exit_code, 4)

    def test_analyzer_executable_inside_product_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self.make_project(root)
            config_path, _, run_pin, _ = self.make_config(root)
            fake = project / "dart.exe"
            fake.write_bytes(b"untrusted")
            with mock.patch("guardian_core.flutter_runner.shutil.which", side_effect=lambda name: str(fake) if name == "dart" else None):
                with self.assertRaisesRegex(FlutterRunnerIntegrityError, "[Pp]rofile-bound|identity|product"):
                    run_flutter_analysis(project_root=project, adapter_config_path=config_path, run_pin=run_pin)


if __name__ == "__main__":
    unittest.main()

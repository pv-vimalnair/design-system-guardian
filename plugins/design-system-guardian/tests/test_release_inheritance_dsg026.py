from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
OUTPUT_LIMIT = 16_384
TAG_SUITES = {
    "v0.3.2": (
        "tests.test_foundation_contract",
        "tests.test_policy",
        "tests.test_working_file_instances_dsg016",
    ),
    "v0.3.3": (
        "tests.test_audit_lane_separation_dsg017",
        "tests.test_ux_evaluator_dsg017",
    ),
    "v0.3.4": (
        "tests.test_rules_foundation_dsg018",
        "tests.test_rule_contract_integration_dsg020",
    ),
    "v0.3.5": (
        "tests.test_rule_activation_dsg025",
        "tests.test_v035_compatibility_contract.V035CompatibilityContractTest."
        "test_immutable_policy_and_two_skill_surface_are_unchanged",
        "tests.test_v035_compatibility_contract.V035CompatibilityContractTest."
        "test_all_legacy_schema_contracts_remain_and_v1_contracts_stay_explicit",
        "tests.test_v035_skill_contracts",
    ),
}


def _bounded(value: bytes) -> str:
    return value[-OUTPUT_LIMIT:].decode("utf-8", errors="replace")


def run_worker(
    plugin_root: Path,
    modules: tuple[str, ...],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(plugin_root)
    command = [sys.executable, "-m", "unittest", *modules, "-v"]
    try:
        completed = runner(
            command,
            cwd=plugin_root,
            env=environment,
            capture_output=True,
            check=False,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "infrastructure_error",
            "returnCode": None,
            "stdout": "",
            "stderr": str(error),
        }
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "returnCode": completed.returncode,
        "stdout": _bounded(completed.stdout),
        "stderr": _bounded(completed.stderr),
    }


def _extract_archive(archive: bytes, destination: Path) -> Path:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise AssertionError("historical archive attempted path traversal")
            if member.issym() or member.islnk():
                raise AssertionError("historical archive contains a redirected entry")
            bundle.extract(member, destination)
    return destination / "plugins" / "design-system-guardian" / "tests"


def run_tag_suite(tag: str, modules: tuple[str, ...]) -> dict[str, Any]:
    archive = subprocess.run(
        [
            "git",
            "archive",
            "--format=tar",
            tag,
            "plugins/design-system-guardian/tests",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
    )
    if archive.returncode != 0:
        return {
            "status": "infrastructure_error",
            "returnCode": archive.returncode,
            "stdout": _bounded(archive.stdout),
            "stderr": _bounded(archive.stderr),
        }
    with tempfile.TemporaryDirectory(prefix=f"guardian-{tag}-") as temp_dir:
        staging_root = Path(temp_dir)
        historical_tests = _extract_archive(archive.stdout, staging_root / "archive")
        current_root = staging_root / "current" / "plugins" / "design-system-guardian"
        shutil.copytree(
            PLUGIN_ROOT,
            current_root,
            ignore=shutil.ignore_patterns(
                "__pycache__", ".dart_tool", ".pytest_cache", "build"
            ),
        )
        shutil.rmtree(current_root / "tests")
        shutil.copytree(historical_tests, current_root / "tests")
        return run_worker(current_root, modules)


class ReleaseInheritanceTest(unittest.TestCase):
    def test_public_v032_through_v035_behavior_executes(self) -> None:
        for tag, modules in TAG_SUITES.items():
            with self.subTest(tag=tag):
                result = run_tag_suite(tag, modules)
                self.assertEqual(
                    result["status"],
                    "passed",
                    f"{tag} inheritance failed: {result}",
                )

    def test_worker_api_failure_is_reported_without_crashing_the_harness(self) -> None:
        def failed_worker(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=b"ordinary assertion output",
                stderr=b"missing historical worker API",
            )

        result = run_worker(
            PLUGIN_ROOT,
            ("tests.does_not_matter",),
            runner=failed_worker,
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["returnCode"], 1)
        self.assertIn("missing historical worker API", result["stderr"])


if __name__ == "__main__":
    unittest.main()

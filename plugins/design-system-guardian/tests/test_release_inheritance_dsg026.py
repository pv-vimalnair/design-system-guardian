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
V036_PUBLIC_COMMIT = "d447b3e344905bbdb0dc23890ba524cbb9622338"
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
    "v0.3.6": (
        "tests.test_usage_rules_audit_lane_dsg026.UsageRulesAuditLaneTest."
        "test_v1_output_remains_exact_and_v2_projects_back_to_it",
        "tests.test_usage_rules_audit_lane_dsg026.UsageRulesAuditLaneTest."
        "test_truth_table_and_informative_rules_are_non_gating",
        "tests.test_analysis_attestation_dsg010.AnalysisAttestationTest."
        "test_exact_runner_and_audit_binding_verifies",
        "tests.test_enforcement_authority_dsg012.EnforcementAuthorityLaneTest."
        "test_v01_audit_has_exact_fail_closed_authority_lane",
        "tests.test_v036_public_contract.V036PublicContractTest."
        "test_package_exposes_exactly_two_canonical_agent_skills",
        "tests.test_v036_public_contract.V036PublicContractTest."
        "test_immutable_policy_digest_is_unchanged",
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


def _resolve_public_tag_commit(
    tag: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> str:
    try:
        completed = runner(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise AssertionError(f"Public tag {tag} could not be resolved: {error}") from error
    if completed.returncode != 0:
        raise AssertionError(
            f"Public tag {tag} could not be resolved: {_bounded(completed.stderr)}"
        )
    commit = completed.stdout.decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise AssertionError(f"Public tag {tag} did not resolve to a commit SHA.")
    return commit


def _archive_ref_for_tag(
    tag: str,
    *,
    resolver: Callable[[str], str] = _resolve_public_tag_commit,
) -> str:
    if tag != "v0.3.6":
        return tag
    resolved = resolver(tag)
    if resolved != V036_PUBLIC_COMMIT:
        raise AssertionError(
            f"Public tag {tag} moved: expected {V036_PUBLIC_COMMIT}, got {resolved}."
        )
    return V036_PUBLIC_COMMIT


def run_tag_suite(tag: str, modules: tuple[str, ...]) -> dict[str, Any]:
    try:
        archive_ref = _archive_ref_for_tag(tag)
    except AssertionError as error:
        return {
            "status": "infrastructure_error",
            "returnCode": None,
            "stdout": "",
            "stderr": str(error),
        }
    archive = subprocess.run(
        [
            "git",
            "archive",
            "--format=tar",
            archive_ref,
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
    def test_v036_public_tag_and_archive_ref_are_immutably_pinned(self) -> None:
        self.assertEqual(
            _resolve_public_tag_commit("v0.3.6"),
            V036_PUBLIC_COMMIT,
        )
        self.assertEqual(
            _archive_ref_for_tag(
                "v0.3.6",
                resolver=lambda _: V036_PUBLIC_COMMIT,
            ),
            V036_PUBLIC_COMMIT,
        )
        with self.assertRaisesRegex(AssertionError, "moved"):
            _archive_ref_for_tag(
                "v0.3.6",
                resolver=lambda _: "a" * 40,
            )

    def test_public_v032_through_v036_behavior_executes(self) -> None:
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

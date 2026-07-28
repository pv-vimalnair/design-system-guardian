from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v8.py"
PRIOR_SUITE_DIGEST = "fab9e47f0e7d26428ee28bafc1055dd7f7aea8e98e0ffb2086a2b12890ec757b"
V8_MODULE_ID = "guardian-public-cases-v8"
V8_CASES = {
    "synthetic-correctness-personal-selection-exact-partition": (
        "correctness",
        10,
        "case_correctness_personal_selection_exact_partition",
    ),
    "synthetic-correctness-personal-preflight-v2-binding": (
        "correctness",
        10,
        "case_correctness_personal_preflight_v2_binding",
    ),
    "synthetic-reliability-new-run-requires-selection": (
        "reliability",
        10,
        "case_reliability_new_run_requires_selection",
    ),
    "synthetic-reliability-permission-drift-rejected": (
        "reliability",
        10,
        "case_reliability_permission_drift_rejected",
    ),
    "synthetic-safety-unknown-source-rejected": (
        "safety_privacy_integrity",
        10,
        "case_safety_unknown_source_rejected",
    ),
    "synthetic-safety-personal-selection-privacy-gate": (
        "safety_privacy_integrity",
        10,
        "case_safety_personal_selection_privacy_gate",
    ),
    "synthetic-coverage-enterprise-preflight-stays-v1": (
        "coverage_usefulness",
        9,
        "case_coverage_enterprise_preflight_stays_v1",
    ),
    "synthetic-portability-selection-cli-and-two-skills": (
        "portability_usability_performance",
        8,
        "case_portability_selection_cli_and_two_skills",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v8_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v8",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _result(suite: dict, v8_status: str, other_status: str = "passed") -> dict:
    return {
        "cases": [
            {
                "achievementId": item["achievementId"],
                "repetitions": [
                    {
                        "repetition": repetition,
                        "status": (
                            v8_status
                            if item["caseModuleId"] == V8_MODULE_ID
                            else other_status
                        ),
                    }
                    for repetition in (1, 2)
                ],
            }
            for item in suite["achievements"]
        ]
    }


class WeightedEloV8EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_and_keeps_local_score_outside_git(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import (
            _current_score,
            _validate_suite_transition,
            _worker_digest,
        )

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(suite["suiteVersion"], 8)

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertIn(V8_MODULE_ID, modules)
        self.assertEqual(
            modules[V8_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V8_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V8_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V8_CASES))
        for achievement_id, (category, weight, function) in V8_CASES.items():
            definition = definitions[achievement_id]
            self.assertEqual(
                (
                    definition["category"],
                    definition["weight"],
                    definition["caseFunction"],
                ),
                (category, weight, function),
            )
            self.assertGreater(definition["weight"], 1)
            self.assertEqual(definition["workerDigest"], _worker_digest())

        previous = copy.deepcopy(suite)
        previous["suiteVersion"] = 7
        previous["caseModules"] = [
            item
            for item in previous["caseModules"]
            if item["moduleId"] != V8_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V8_MODULE_ID
        ]
        self.assertEqual(sha256_digest(previous), PRIOR_SUITE_DIGEST)
        _validate_suite_transition(previous, suite)

        self.assertEqual(current["score"], 1)
        self.assertEqual(current["achievementIds"], [])
        self.assertEqual(current["suiteSnapshot"]["suiteVersion"], 3)
        self.assertEqual(_current_score(), current)

    def test_cases_are_stdlib_only_synthetic_and_pass_current_checkout(self) -> None:
        from guardian_core.elo import _WORKER

        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            str(node.module).split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertLessEqual(
            imported_roots,
            {
                "__future__",
                "contextlib",
                "copy",
                "importlib",
                "json",
                "pathlib",
                "sys",
                "tempfile",
                "typing",
            },
        )
        for forbidden in (
            "ExamplePrivateCompany",
            "ExamplePrivateProduct",
            "PrivateReleaseCandidate",
            "C:" + chr(92),
            "/Users/",
            "@example.com",
        ):
            self.assertNotIn(forbidden, source)

        module = _load_v8_module()
        functions = sorted(name for name in vars(module) if name.startswith("case_"))
        self.assertEqual(functions, sorted(value[2] for value in V8_CASES.values()))
        for function in functions:
            for repetition in (1, 2):
                with self.subTest(function=function, repetition=repetition):
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-B",
                            "-c",
                            _WORKER,
                            str(MODULE_PATH),
                            function,
                            str(ROOT),
                        ],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(
                        (completed.returncode, completed.stdout, completed.stderr),
                        (0, b"", b""),
                    )

    def test_weighted_progress_is_bounded_and_regressible(self) -> None:
        from guardian_core.elo import _derive_evaluation

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        baseline = _result(suite, "assertion_failed")
        candidate = _result(suite, "passed")
        progress = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertGreater(progress["delta"], len(V8_CASES))
        self.assertLessEqual(progress["score"], 2000)
        self.assertEqual(set(progress["newAchievementIds"]), set(V8_CASES))

        no_change = _derive_evaluation([], 1, suite, candidate, candidate)
        self.assertEqual((no_change["delta"], no_change["score"]), (0, 1))

        regression = _derive_evaluation(
            sorted(V8_CASES),
            1000,
            suite,
            candidate,
            baseline,
        )
        self.assertLess(regression["delta"], 0)
        self.assertLess(regression["score"], 1000)
        self.assertEqual(
            set(regression["confirmedRegressionIds"]),
            set(V8_CASES),
        )


if __name__ == "__main__":
    unittest.main()

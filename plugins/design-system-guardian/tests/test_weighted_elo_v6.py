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
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v6.py"
PRIOR_SUITE_DIGEST = "d96c5d3f5efc34898410ae1331f20adedece5bcc8cad749ee924acb1e3000767"
V6_MODULE_ID = "guardian-public-cases-v6"
V7_MODULE_ID = "guardian-public-cases-v7"
V6_CASES = {
    "synthetic-correctness-explicit-evaluator-v2": (
        "correctness",
        8,
        "case_correctness_explicit_evaluator_v2",
    ),
    "synthetic-reliability-no-implicit-evaluator-upgrade": (
        "reliability",
        7,
        "case_reliability_no_implicit_evaluator_upgrade",
    ),
    "synthetic-coverage-six-predicates-two-scopes": (
        "coverage_usefulness",
        8,
        "case_coverage_six_predicates_two_scopes",
    ),
    "synthetic-safety-separate-usage-rules-lane": (
        "safety_privacy_integrity",
        8,
        "case_safety_separate_usage_rules_lane",
    ),
    "synthetic-portability-rule-list-reload-status": (
        "portability_usability_performance",
        7,
        "case_portability_rule_list_reload_status",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v6_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v6", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WeightedEloV6EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_and_keeps_local_score_outside_git(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _current_score, _validate_suite_transition, _worker_digest

        current_suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(current_suite["suiteVersion"], 7)
        suite = copy.deepcopy(current_suite)
        suite["suiteVersion"] = 6
        suite["caseModules"] = [
            item for item in suite["caseModules"] if item["moduleId"] != V7_MODULE_ID
        ]
        suite["achievements"] = [
            item
            for item in suite["achievements"]
            if item["caseModuleId"] != V7_MODULE_ID
        ]

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertEqual(
            set(modules),
            {
                "guardian-public-cases-v1",
                "guardian-public-cases-v3",
                "guardian-public-cases-v4",
                "guardian-public-cases-v5",
                V6_MODULE_ID,
            },
        )
        self.assertEqual(
            modules[V6_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V6_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V6_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V6_CASES))
        for achievement_id, (category, weight, function) in V6_CASES.items():
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
        previous["suiteVersion"] = 5
        previous["caseModules"] = [
            item for item in previous["caseModules"] if item["moduleId"] != V6_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V6_MODULE_ID
        ]
        self.assertEqual(sha256_digest(previous), PRIOR_SUITE_DIGEST)
        _validate_suite_transition(previous, suite)

        self.assertEqual(current["score"], 1)
        self.assertEqual(current["achievementIds"], [])
        self.assertEqual(current["suiteSnapshot"]["suiteVersion"], 3)
        self.assertEqual(_current_score(), current)

    def test_cases_are_stdlib_only_and_execute_deterministically(self) -> None:
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
            "C:" + chr(92),
            "/Users/",
            "@example.com",
        ):
            self.assertNotIn(forbidden, source)

        module = _load_v6_module()
        functions = sorted(name for name in vars(module) if name.startswith("case_"))
        self.assertEqual(functions, sorted(value[2] for value in V6_CASES.values()))
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
                    expected_code = (
                        1
                        if function == "case_portability_rule_list_reload_status"
                        else 0
                    )
                    self.assertEqual(
                        (completed.returncode, completed.stdout, completed.stderr),
                        (expected_code, b"", b""),
                    )

    def test_weighted_v036_progress_is_material_and_bounded(self) -> None:
        from guardian_core.elo import _derive_evaluation

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        cases = []
        for item in suite["achievements"]:
            is_v6 = item["caseModuleId"] == V6_MODULE_ID
            cases.append(
                {
                    "achievementId": item["achievementId"],
                    "repetitions": [
                        {
                            "repetition": repetition,
                            "status": "assertion_failed" if is_v6 else "passed",
                        }
                        for repetition in (1, 2)
                    ],
                }
            )
        baseline = {"cases": cases}
        candidate = copy.deepcopy(baseline)
        for item in candidate["cases"]:
            if item["achievementId"] in V6_CASES:
                for repetition in item["repetitions"]:
                    repetition["status"] = "passed"

        result = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertGreater(result["delta"], len(V6_CASES))
        self.assertLessEqual(result["score"], 2000)
        self.assertEqual(set(result["newAchievementIds"]), set(V6_CASES))


if __name__ == "__main__":
    unittest.main()

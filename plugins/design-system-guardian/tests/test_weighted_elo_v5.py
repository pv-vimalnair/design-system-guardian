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
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v5.py"
PRIOR_SUITE_DIGEST = "5f77c8c1998d35697cea1c21c01b28c955870a2f895461ff16b0cbcf9e99df34"
V5_MODULE_ID = "guardian-public-cases-v5"
V5_CASES = {
    "synthetic-correctness-safe-rule-activation": (
        "correctness",
        6,
        "case_correctness_safe_rule_activation",
    ),
    "synthetic-reliability-v1-state-preserved": (
        "reliability",
        6,
        "case_reliability_v1_state_preserved",
    ),
    "synthetic-coverage-first-predicate-pairs": (
        "coverage_usefulness",
        5,
        "case_coverage_first_predicate_pairs",
    ),
    "synthetic-safety-permission-is-not-rule-approval": (
        "safety_privacy_integrity",
        7,
        "case_safety_permission_is_not_rule_approval",
    ),
    "synthetic-portability-no-downgrade": (
        "portability_usability_performance",
        5,
        "case_portability_no_downgrade",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v5_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v5", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WeightedEloV5EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_and_keeps_public_genesis(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _current_score, _validate_suite_transition, _worker_digest

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(suite["suiteVersion"], 5)

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertEqual(
            set(modules),
            {
                "guardian-public-cases-v1",
                "guardian-public-cases-v3",
                "guardian-public-cases-v4",
                V5_MODULE_ID,
            },
        )
        self.assertEqual(
            modules[V5_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V5_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V5_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V5_CASES))
        for achievement_id, (category, weight, function) in V5_CASES.items():
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
        previous["suiteVersion"] = 4
        previous["caseModules"] = [
            item for item in previous["caseModules"] if item["moduleId"] != V5_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V5_MODULE_ID
        ]
        self.assertEqual(sha256_digest(previous), PRIOR_SUITE_DIGEST)
        _validate_suite_transition(previous, suite)

        self.assertEqual(current["score"], 1)
        self.assertEqual(current["achievementIds"], [])
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
        ):
            self.assertNotIn(forbidden, source)

        module = _load_v5_module()
        functions = sorted(name for name in vars(module) if name.startswith("case_"))
        self.assertEqual(functions, sorted(value[2] for value in V5_CASES.values()))
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

    def test_weighted_safe_activation_progress_is_material_and_bounded(self) -> None:
        from guardian_core.elo import _derive_evaluation

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        cases = []
        for item in suite["achievements"]:
            is_v5 = item["caseModuleId"] == V5_MODULE_ID
            cases.append(
                {
                    "achievementId": item["achievementId"],
                    "repetitions": [
                        {
                            "repetition": repetition,
                            "status": "assertion_failed" if is_v5 else "passed",
                        }
                        for repetition in (1, 2)
                    ],
                }
            )
        baseline = {"cases": cases}
        candidate = copy.deepcopy(baseline)
        for item in candidate["cases"]:
            if item["achievementId"] in V5_CASES:
                for repetition in item["repetitions"]:
                    repetition["status"] = "passed"

        result = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertGreater(result["delta"], len(V5_CASES))
        self.assertLessEqual(result["score"], 2000)
        self.assertEqual(set(result["newAchievementIds"]), set(V5_CASES))


if __name__ == "__main__":
    unittest.main()

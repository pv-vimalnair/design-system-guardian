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
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v4.py"
PRIOR_SUITE_DIGEST = "debcf5e126a100144209a47303d86463e0f9f1f9a3374bb9a2c4274e7071dde7"
V4_MODULE_ID = "guardian-public-cases-v4"
V4_CASES = {
    "synthetic-correctness-explicit-rules-fail-closed": (
        "correctness",
        5,
        "case_correctness_explicit_rules_fail_closed",
    ),
    "synthetic-reliability-deterministic-rule-preview": (
        "reliability",
        4,
        "case_reliability_deterministic_rule_preview",
    ),
    "synthetic-coverage-six-rule-predicates": (
        "coverage_usefulness",
        4,
        "case_coverage_six_rule_predicates",
    ),
    "synthetic-safety-rule-preview-nondisclosure": (
        "safety_privacy_integrity",
        5,
        "case_safety_rule_preview_nondisclosure",
    ),
    "synthetic-usability-rule-cli-contract": (
        "portability_usability_performance",
        4,
        "case_usability_rule_cli_contract",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v4_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v4", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WeightedEloV4EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_and_keeps_public_genesis(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _current_score, _validate_suite_transition, _worker_digest

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(suite["suiteVersion"], 4)

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertEqual(
            set(modules),
            {"guardian-public-cases-v1", "guardian-public-cases-v3", V4_MODULE_ID},
        )
        self.assertEqual(
            modules[V4_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V4_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V4_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V4_CASES))
        for achievement_id, (category, weight, function) in V4_CASES.items():
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
        previous["suiteVersion"] = 3
        previous["caseModules"] = [
            item for item in previous["caseModules"] if item["moduleId"] != V4_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V4_MODULE_ID
        ]
        self.assertEqual(sha256_digest(previous), PRIOR_SUITE_DIGEST)
        _validate_suite_transition(previous, suite)

        self.assertEqual(current["score"], 1)
        self.assertEqual(current["achievementIds"], [])
        self.assertEqual(current["suiteSnapshot"], previous)
        self.assertEqual(current["suiteDigest"], PRIOR_SUITE_DIGEST)
        self.assertEqual(_current_score(), current)

    def test_cases_are_stdlib_only_public_and_pass_the_current_checkout(self) -> None:
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
                "io",
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
            "ExamplePrivatePerson",
            "C:" + chr(92),
            "/Users/",
        ):
            self.assertNotIn(forbidden, source)

        module = _load_v4_module()
        functions = sorted(name for name in vars(module) if name.startswith("case_"))
        self.assertEqual(functions, sorted(value[2] for value in V4_CASES.values()))
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

    def test_weights_produce_material_but_bounded_progress(self) -> None:
        from guardian_core.elo import _derive_evaluation

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        cases = []
        for item in suite["achievements"]:
            is_v4 = item["caseModuleId"] == V4_MODULE_ID
            cases.append(
                {
                    "achievementId": item["achievementId"],
                    "repetitions": [
                        {
                            "repetition": repetition,
                            "status": "assertion_failed" if is_v4 else "passed",
                        }
                        for repetition in (1, 2)
                    ],
                }
            )
        baseline = {"cases": cases}
        candidate = copy.deepcopy(baseline)
        for item in candidate["cases"]:
            if item["achievementId"] in V4_CASES:
                for repetition in item["repetitions"]:
                    repetition["status"] = "passed"

        result = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertEqual(
            result["categoryDeltas"],
            {
                "correctness": 31,
                "reliability": 16,
                "coverage_usefulness": 20,
                "safety_privacy_integrity": 12,
                "portability_usability_performance": 4,
            },
        )
        self.assertEqual(result["delta"], 83)
        self.assertEqual(result["score"], 84)
        self.assertEqual(set(result["newAchievementIds"]), set(V4_CASES))


if __name__ == "__main__":
    unittest.main()

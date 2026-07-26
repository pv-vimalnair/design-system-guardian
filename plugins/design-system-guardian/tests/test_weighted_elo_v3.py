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
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v3.py"
PRIOR_SUITE_DIGEST = "546c02d9c207d7108b4bb477c31e28541de83f63a2ee5fd2433fee163579cdf4"
V3_MODULE_ID = "guardian-public-cases-v3"
V3_CASES = {
    "synthetic-correctness-figma-bound-duplicates": (
        "correctness",
        6,
        "case_correctness_figma_bound_duplicates",
    ),
    "synthetic-reliability-ux-positive-downgrade": (
        "reliability",
        4,
        "case_reliability_ux_positive_downgrade",
    ),
    "synthetic-safety-private-figma-evidence": (
        "safety_privacy_integrity",
        6,
        "case_safety_private_figma_evidence",
    ),
    "synthetic-usability-permission-bound-onboarding": (
        "portability_usability_performance",
        4,
        "case_usability_permission_bound_onboarding",
    ),
    "synthetic-portability-permissioned-runtime-bootstrap": (
        "portability_usability_performance",
        5,
        "case_portability_permissioned_runtime_bootstrap",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v3_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v3", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WeightedEloV3EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_immutable_and_keeps_public_genesis(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _validate_suite_transition, _worker_digest

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(suite["suiteVersion"], 3)

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertEqual(set(modules), {"guardian-public-cases-v1", V3_MODULE_ID})
        self.assertEqual(
            modules[V3_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V3_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V3_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V3_CASES))
        for achievement_id, (category, weight, function) in V3_CASES.items():
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
        previous["suiteVersion"] = 2
        previous["caseModules"] = [
            item
            for item in previous["caseModules"]
            if item["moduleId"] != V3_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V3_MODULE_ID
        ]
        self.assertEqual(sha256_digest(previous), PRIOR_SUITE_DIGEST)
        _validate_suite_transition(previous, suite)

        self.assertEqual(current["score"], 1)
        self.assertEqual(current["achievementIds"], [])
        self.assertEqual(current["suiteSnapshot"], suite)
        self.assertEqual(current["suiteDigest"], sha256_digest(suite))

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
                "copy",
                "hashlib",
                "importlib",
                "json",
                "pathlib",
                "subprocess",
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

        module = _load_v3_module()
        functions = sorted(
            name for name in vars(module) if name.startswith("case_")
        )
        self.assertEqual(
            functions,
            sorted(value[2] for value in V3_CASES.values()),
        )
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
            is_v3 = item["caseModuleId"] == V3_MODULE_ID
            cases.append(
                {
                    "achievementId": item["achievementId"],
                    "repetitions": [
                        {
                            "repetition": repetition,
                            "status": "assertion_failed" if is_v3 else "passed",
                        }
                        for repetition in (1, 2)
                    ],
                }
            )
        baseline = {"cases": cases}
        candidate = copy.deepcopy(baseline)
        for item in candidate["cases"]:
            if item["achievementId"] in V3_CASES:
                for repetition in item["repetitions"]:
                    repetition["status"] = "passed"

        result = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertEqual(
            result["categoryDeltas"],
            {
                "correctness": 60,
                "reliability": 27,
                "coverage_usefulness": 0,
                "safety_privacy_integrity": 23,
                "portability_usability_performance": 11,
            },
        )
        self.assertEqual(result["delta"], 121)
        self.assertEqual(result["score"], 122)
        self.assertEqual(set(result["newAchievementIds"]), set(V3_CASES))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "benchmarks" / "elo_cases_v7.py"
PRIOR_SUITE_DIGEST = "29f2eb0ff0b8aca5c1d5b098a7226f0c8b707ef95c0c638d997dd00a2f20606c"
V7_MODULE_ID = "guardian-public-cases-v7"
V7_CASES = {
    "synthetic-correctness-complete-judgment-assessment": (
        "correctness", 9, "case_correctness_complete_judgment_assessment",
    ),
    "synthetic-correctness-positive-judgment-approval": (
        "correctness", 9, "case_correctness_positive_judgment_approval",
    ),
    "synthetic-coverage-selected-judgment-exception": (
        "coverage_usefulness", 8, "case_coverage_selected_judgment_exception",
    ),
    "synthetic-reliability-judgment-revocation": (
        "reliability", 9, "case_reliability_judgment_revocation",
    ),
    "synthetic-reliability-judgment-replay-rejection": (
        "reliability", 9, "case_reliability_judgment_replay_rejection",
    ),
    "synthetic-safety-hard-lane-non-override": (
        "safety_privacy_integrity", 10, "case_safety_hard_lane_non_override",
    ),
    "synthetic-safety-local-judgment-privacy": (
        "safety_privacy_integrity", 10, "case_safety_local_judgment_privacy",
    ),
    "synthetic-portability-four-judgment-commands": (
        "portability_usability_performance", 8,
        "case_portability_four_judgment_commands",
    ),
}


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _load_v7_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "guardian_public_elo_cases_v7", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _materialize_tag_plugin(parent: Path, tag: str) -> Path:
    repository = ROOT.parents[1]
    target = parent / "historical-plugin"
    target.mkdir()
    prefix = "plugins/design-system-guardian/"
    raw = subprocess.check_output(
        ["git", "ls-tree", "-rz", tag, "--", prefix], cwd=repository
    )
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        _mode, kind, blob = metadata.decode("ascii").split()
        if kind != "blob":
            continue
        relative = name.decode("utf-8")[len(prefix):]
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            subprocess.check_output(
                ["git", "cat-file", "blob", blob], cwd=repository
            )
        )
    return target


def _result(suite: dict, v7_status: str, other_status: str = "passed") -> dict:
    return {
        "cases": [
            {
                "achievementId": item["achievementId"],
                "repetitions": [
                    {
                        "repetition": repetition,
                        "status": (
                            v7_status
                            if item["caseModuleId"] == V7_MODULE_ID
                            else other_status
                        ),
                    }
                    for repetition in (1, 2)
                ],
            }
            for item in suite["achievements"]
        ]
    }


class WeightedEloV7EvolutionTest(unittest.TestCase):
    def test_suite_evolution_is_additive_and_keeps_local_score_outside_git(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _current_score, _validate_suite_transition, _worker_digest

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        current = _json(ROOT / "benchmarks" / "current-score.json")
        self.assertEqual(suite["suiteVersion"], 7)

        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        self.assertEqual(
            set(modules),
            {
                "guardian-public-cases-v1",
                "guardian-public-cases-v3",
                "guardian-public-cases-v4",
                "guardian-public-cases-v5",
                "guardian-public-cases-v6",
                V7_MODULE_ID,
            },
        )
        self.assertEqual(
            modules[V7_MODULE_ID]["moduleDigest"],
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(modules[V7_MODULE_ID]["workerDigest"], _worker_digest())

        definitions = {
            item["achievementId"]: item
            for item in suite["achievements"]
            if item["caseModuleId"] == V7_MODULE_ID
        }
        self.assertEqual(set(definitions), set(V7_CASES))
        for achievement_id, (category, weight, function) in V7_CASES.items():
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
        previous["suiteVersion"] = 6
        previous["caseModules"] = [
            item for item in previous["caseModules"] if item["moduleId"] != V7_MODULE_ID
        ]
        previous["achievements"] = [
            item
            for item in previous["achievements"]
            if item["caseModuleId"] != V7_MODULE_ID
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
            "C:" + chr(92),
            "/Users/",
            "@example.com",
        ):
            self.assertNotIn(forbidden, source)

        module = _load_v7_module()
        functions = sorted(name for name in vars(module) if name.startswith("case_"))
        self.assertEqual(functions, sorted(value[2] for value in V7_CASES.values()))
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

    def test_four_command_case_fails_quietly_on_v036(self) -> None:
        from guardian_core.elo import _WORKER

        with tempfile.TemporaryDirectory() as directory:
            target = _materialize_tag_plugin(Path(directory), "v0.3.6")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    _WORKER,
                    str(MODULE_PATH),
                    "case_portability_four_judgment_commands",
                    str(target),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                (completed.returncode, completed.stdout, completed.stderr),
                (1, b"", b""),
            )

    def test_weighted_progress_is_bounded_regressible_and_not_test_count_inflated(self) -> None:
        from guardian_core.elo import _derive_evaluation

        suite = _json(ROOT / "benchmarks" / "elo-suite.json")
        baseline = _result(suite, "assertion_failed")
        candidate = _result(suite, "passed")
        progress = _derive_evaluation([], 1, suite, baseline, candidate)
        self.assertGreater(progress["delta"], len(V7_CASES))
        self.assertLessEqual(progress["score"], 2000)
        self.assertEqual(set(progress["newAchievementIds"]), set(V7_CASES))

        no_change = _derive_evaluation([], 1, suite, candidate, candidate)
        self.assertEqual((no_change["delta"], no_change["score"]), (0, 1))

        regression = _derive_evaluation(
            sorted(V7_CASES), 1000, suite, candidate, baseline
        )
        self.assertLess(regression["delta"], 0)
        self.assertLess(regression["score"], 1000)
        self.assertEqual(set(regression["confirmedRegressionIds"]), set(V7_CASES))


if __name__ == "__main__":
    unittest.main()

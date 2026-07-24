from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

from tests.guardian_test_support import catalog_authority_public_key_path


ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks" / "elo-suite.json"
CURRENT_SCORE_PATH = ROOT / "benchmarks" / "current-score.json"
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
RUNTIME_DIGEST = "9" * 64
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


def _provision(home: Path) -> None:
    from guardian_core.policy import install_policy_anchor

    install_policy_anchor(
        home,
        catalog_authority_public_key=catalog_authority_public_key_path(home),
    )


def _suite() -> dict:
    return json.loads(SUITE_PATH.read_text(encoding="utf-8"))


def _result(
    passed: list[str],
    *,
    version: str,
    commit: str,
    regressions: list[dict] | None = None,
    runtime_digest: str = RUNTIME_DIGEST,
) -> dict:
    from guardian_core.canonical import sha256_digest

    return {
        "schemaVersion": 1,
        "model": "guardian-weighted-elo-v1",
        "suiteDigest": sha256_digest(_suite()),
        "policyDigest": POLICY_DIGEST,
        "runtimeDigest": runtime_digest,
        "pluginVersion": version,
        "sourceCommit": commit,
        "passedAchievementIds": sorted(passed),
        "regressions": [] if regressions is None else regressions,
    }


def _confirmed_regression(achievement_id: str) -> dict:
    return {
        "achievementId": achievement_id,
        "attribution": "guardian",
        "conditionDigest": "c" * 64,
        "reproductionDigests": ["d" * 64, "e" * 64],
    }


class WeightedEloArithmeticTest(unittest.TestCase):
    def test_constants_and_new_install_start_at_one(self) -> None:
        from guardian_core.elo import ELO_MAX, ELO_MIN, ELO_WEIGHTS, read_elo_state

        self.assertEqual(
            ELO_WEIGHTS,
            {
                "correctness": 80,
                "reliability": 40,
                "coverage_usefulness": 30,
                "safety_privacy_integrity": 30,
                "portability_usability_performance": 20,
            },
        )
        self.assertEqual((ELO_MIN, ELO_MAX), (1, 2000))
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                read_elo_state(Path(directory)),
                {
                    "schemaVersion": 1,
                    "model": "guardian-weighted-elo-v1",
                    "score": 1,
                    "sequence": 0,
                    "entryDigest": None,
                    "achievementIds": [],
                },
            )

    def test_score_bounds_are_exact(self) -> None:
        from guardian_core.elo import _bounded_score

        self.assertEqual(_bounded_score(1950, 200), 2000)
        self.assertEqual(_bounded_score(30, -200), 1)

    def test_zero_change_is_zero_and_positive_uses_integer_half_up_rounding(self) -> None:
        from guardian_core.elo import evaluate_elo

        suite = _suite()
        ids = [item["achievementId"] for item in suite["achievements"]]
        portability = [
            item["achievementId"]
            for item in suite["achievements"]
            if item["category"] == "portability_usability_performance"
        ]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            baseline = _result([], version="0.2.0", commit=COMMIT_A)
            unchanged = evaluate_elo(
                home,
                baseline,
                _result([], version="0.2.1", commit=COMMIT_B),
            )
            self.assertEqual(unchanged["delta"], 0)
            self.assertEqual(unchanged["score"], 1)
            one_of_eight = evaluate_elo(
                home,
                baseline,
                _result([portability[0]], version="0.2.2", commit=COMMIT_B),
            )
            self.assertEqual(one_of_eight["categoryDeltas"]["portability_usability_performance"], 3)
            self.assertEqual(one_of_eight["delta"], 3)
            self.assertEqual(one_of_eight["score"], 4)
            all_positive = evaluate_elo(
                home,
                _result([portability[0]], version="0.2.2", commit=COMMIT_B),
                _result(ids, version="0.3.0", commit=COMMIT_A),
            )
            self.assertEqual(all_positive["delta"], 198)
            self.assertEqual(all_positive["score"], 202)

    def test_achievement_is_awarded_once_and_score_is_bounded(self) -> None:
        from guardian_core.elo import evaluate_elo

        ids = [item["achievementId"] for item in _suite()["achievements"]]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            baseline = _result([], version="0.2.0", commit=COMMIT_A)
            candidate = _result(ids, version="0.3.0", commit=COMMIT_B)
            first = evaluate_elo(home, baseline, candidate)
            second = evaluate_elo(home, baseline, candidate)
            self.assertEqual(first["delta"], 200)
            self.assertEqual(second["delta"], 0)
            self.assertEqual(second["score"], 201)
            state = first
            for index in range(12):
                state = evaluate_elo(
                    home,
                    baseline,
                    _result(ids, version=f"1.{index}.0", commit=COMMIT_A),
                )
            self.assertLessEqual(state["score"], 2000)

    def test_negative_requires_two_same_condition_guardian_reproductions(self) -> None:
        from guardian_core.elo import evaluate_elo

        achievement = _suite()["achievements"][0]["achievementId"]
        baseline = _result([achievement], version="0.2.0", commit=COMMIT_A)
        cases = (
            [],
            [{
                "achievementId": achievement,
                "attribution": "guardian",
                "conditionDigest": "c" * 64,
                "reproductionDigests": ["d" * 64],
            }],
            *(
                [{
                    "achievementId": achievement,
                    "attribution": attribution,
                    "conditionDigest": "c" * 64,
                    "reproductionDigests": ["d" * 64, "e" * 64],
                }]
                for attribution in ("external", "source", "project", "project_configuration")
            ),
        )
        for regressions in cases:
            with self.subTest(regressions=regressions), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                _provision(home)
                candidate = _result([], version="0.2.1", commit=COMMIT_B, regressions=regressions)
                result = evaluate_elo(home, baseline, candidate)
                self.assertEqual(result["delta"], 0)
                self.assertEqual(result["score"], 1)

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            candidate = _result(
                [],
                version="0.2.1",
                commit=COMMIT_B,
                regressions=[_confirmed_regression(achievement)],
            )
            result = evaluate_elo(home, baseline, candidate)
            self.assertLess(result["delta"], 0)
            self.assertEqual(result["score"], 1)

    def test_digest_mismatch_and_unknown_result_fields_fail_closed(self) -> None:
        from guardian_core.elo import EloIntegrityError, evaluate_elo

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            baseline = _result([], version="0.2.0", commit=COMMIT_A)
            candidate = _result([], version="0.2.1", commit=COMMIT_B, runtime_digest="8" * 64)
            with self.assertRaises(EloIntegrityError):
                evaluate_elo(home, baseline, candidate)
            candidate = _result([], version="0.2.1", commit=COMMIT_B)
            candidate["profileId"] = "private-company"
            with self.assertRaises(EloIntegrityError):
                evaluate_elo(home, baseline, candidate)


class WeightedEloIntegrityAndCliTest(unittest.TestCase):
    def invoke(self, home: Path, args: list[str]) -> tuple[int, str, str]:
        from guardian_core.cli import main

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("guardian_core.cli.default_guardian_home", return_value=home),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_history_is_create_once_sealed_chained_and_tamper_evident(self) -> None:
        from guardian_core.elo import EloIntegrityError, evaluate_elo, read_elo_state

        ids = [item["achievementId"] for item in _suite()["achievements"]]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            evaluate_elo(
                home,
                _result([], version="0.2.0", commit=COMMIT_A),
                _result(ids, version="0.3.0", commit=COMMIT_B),
            )
            history = sorted((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
            self.assertEqual(len(history), 1)
            self.assertRegex(history[0].name, r"^00000000000000000001-[0-9a-f]{64}\.sealed\.json$")
            original = history[0].read_bytes()
            ledger_schema = json.loads(
                (ROOT / "schemas" / "evolution" / "elo-ledger-entry.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            Draft202012Validator(ledger_schema).validate(json.loads(original))
            forged = json.loads(original)
            forged["score"] = 999
            history[0].write_text(json.dumps(forged, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            with self.assertRaises(EloIntegrityError):
                read_elo_state(home)
            history[0].write_bytes(original)
            future = json.loads(original)
            future["futureField"] = True
            history[0].write_text(json.dumps(future, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            with self.assertRaises(EloIntegrityError):
                read_elo_state(home)

    def test_public_schemas_are_strict_and_fixtures_are_synthetic(self) -> None:
        schema_root = ROOT / "schemas" / "evolution"
        expected = {"elo-benchmark-result.schema.json", "elo-ledger-entry.schema.json"}
        self.assertEqual({path.name for path in schema_root.glob("*.schema.json")}, expected)
        for name in expected:
            schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            self.assertFalse(schema.get("additionalProperties", True))
        result_schema = json.loads(
            (schema_root / "elo-benchmark-result.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(result_schema).validate(
            _result([], version="0.2.0", commit=COMMIT_A)
        )
        private = _result([], version="0.2.0", commit=COMMIT_A)
        private["company"] = "Acme"
        with self.assertRaises(ValidationError):
            Draft202012Validator(result_schema).validate(private)
        public_text = SUITE_PATH.read_text(encoding="utf-8") + CURRENT_SCORE_PATH.read_text(
            encoding="utf-8"
        )
        for forbidden in ("profileId", "company", "projectRoot", "C:\\", "/Users/"):
            self.assertNotIn(forbidden, public_text)
        current = json.loads(CURRENT_SCORE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(current["score"], 1)
        self.assertEqual(current["model"], "guardian-weighted-elo-v1")

    def test_generic_host_package_includes_public_benchmarks(self) -> None:
        from scripts.install_agent_skills import PACKAGE_ENTRIES

        self.assertIn("benchmarks", PACKAGE_ENTRIES)

    def test_cli_show_and_evaluate_use_explicit_public_results(self) -> None:
        from guardian_core.canonical import atomic_write_json

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            baseline_path = Path(directory) / "baseline.json"
            candidate_path = Path(directory) / "candidate.json"
            code, out, err = self.invoke(home, ["elo", "show"])
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(json.loads(out)["score"], 1)
            _provision(home)
            atomic_write_json(baseline_path, _result([], version="0.2.0", commit=COMMIT_A))
            atomic_write_json(
                candidate_path,
                _result(
                    [item["achievementId"] for item in _suite()["achievements"]],
                    version="0.3.0",
                    commit=COMMIT_B,
                ),
            )
            code, out, err = self.invoke(
                home,
                [
                    "elo",
                    "evaluate",
                    "--baseline-result",
                    str(baseline_path),
                    "--candidate-result",
                    str(candidate_path),
                ],
            )
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(json.loads(out)["delta"], 200)


if __name__ == "__main__":
    unittest.main()

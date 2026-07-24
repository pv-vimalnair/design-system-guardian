from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from tests.guardian_test_support import catalog_authority_public_key_path


ROOT = Path(__file__).resolve().parents[1]


def _provision(home: Path) -> None:
    from guardian_core.policy import install_policy_anchor

    install_policy_anchor(
        home, catalog_authority_public_key=catalog_authority_public_key_path(home)
    )


class WeightedEloContractTest(unittest.TestCase):
    def test_constants_and_new_install_start_at_one(self) -> None:
        from guardian_core.elo import ELO_MAX, ELO_MIN, ELO_WEIGHTS, read_elo_state

        self.assertEqual(ELO_WEIGHTS, {
            "correctness": 80,
            "reliability": 40,
            "coverage_usefulness": 30,
            "safety_privacy_integrity": 30,
            "portability_usability_performance": 20,
        })
        self.assertEqual((ELO_MIN, ELO_MAX), (1, 2000))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            state = read_elo_state(home)
        self.assertEqual((state["score"], state["sequence"]), (1, 0))

    def test_score_bounds_are_exact(self) -> None:
        from guardian_core.elo import _bounded_score

        self.assertEqual(_bounded_score(1950, 200), 2000)
        self.assertEqual(_bounded_score(30, -200), 1)

    def test_public_suite_binds_immutable_executable_modules(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.elo import _public_suite, _worker_digest

        suite, by_id = _public_suite()
        self.assertTrue(by_id)
        modules = {item["moduleId"]: item for item in suite["caseModules"]}
        for module in modules.values():
            self.assertEqual(
                sha256_digest((ROOT / module["path"]).read_bytes()),
                module["moduleDigest"],
            )
            self.assertEqual(module["workerDigest"], _worker_digest())
        for item in suite["achievements"]:
            self.assertIn(item["caseModuleId"], modules)
            self.assertEqual(item["workerDigest"], modules[item["caseModuleId"]]["workerDigest"])
        current = json.loads((ROOT / "benchmarks" / "current-score.json").read_text("utf-8"))
        self.assertEqual(current["schemaVersion"], 3)
        self.assertEqual(current["suiteSnapshot"], suite)
        self.assertEqual(current["suiteDigest"], sha256_digest(suite))
    def test_evolution_schemas_are_strict_v2(self) -> None:
        root = ROOT / "schemas" / "evolution"
        expected = {"elo-benchmark-result.schema.json", "elo-ledger-entry.schema.json"}
        self.assertEqual({path.name for path in root.glob("*.schema.json")}, expected)
        for name in expected:
            schema = json.loads((root / name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            self.assertFalse(schema.get("additionalProperties", True))
            self.assertEqual(schema["properties"]["schemaVersion"], {"const": 2})

    def test_unsealed_caller_authored_pass_list_is_rejected(self) -> None:
        from guardian_core.elo import EloIntegrityError, evaluate_elo

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            forged = {
                "schemaVersion": 2,
                "model": "guardian-weighted-elo-v1",
                "passedAchievementIds": ["synthetic-correctness-exact-identity"],
            }
            with self.assertRaises(EloIntegrityError):
                evaluate_elo(home, forged, forged)

    def test_cli_exposes_show_benchmark_and_evaluate(self) -> None:
        from guardian_core.cli import build_parser, main

        parser = build_parser()
        self.assertEqual(
            parser.parse_args(["elo", "benchmark", "--target-root", "."]).handler.__name__,
            "_elo_benchmark_command",
        )
        self.assertEqual(
            parser.parse_args([
                "elo", "evaluate", "--baseline-result", "a.json",
                "--candidate-result", "b.json",
            ]).handler.__name__,
            "_elo_evaluate_command",
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["elo", "show"])
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertEqual(json.loads(stdout.getvalue())["score"], 1)

    def test_public_package_and_fixtures_remain_generic(self) -> None:
        from scripts.generic_skill_launcher import PACKAGE_ENTRIES as launcher_entries
        from scripts.install_agent_skills import PACKAGE_ENTRIES as installer_entries

        self.assertIn("benchmarks", installer_entries)
        self.assertEqual(installer_entries, launcher_entries)
        public = "".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "benchmarks").glob("*.json"))
        )
        for forbidden in ("profileId", "company", "projectRoot", "C:\\", "/Users/"):
            self.assertNotIn(forbidden, public)


if __name__ == "__main__":
    unittest.main()

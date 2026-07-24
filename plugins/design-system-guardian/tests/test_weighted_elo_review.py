from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tests.guardian_test_support import catalog_authority_public_key_path


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


def _provision(home: Path) -> None:
    from guardian_core.policy import install_policy_anchor

    install_policy_anchor(
        home,
        catalog_authority_public_key=catalog_authority_public_key_path(home),
    )


def _copy(relative: str, target: Path) -> None:
    source = ROOT / relative
    destination = target / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        shutil.copy2(source, destination)


def _make_target(parent: Path, name: str, *, version: str = "0.2.0", third_skill: bool = False) -> Path:
    target = parent / name
    target.mkdir()
    for relative in (
        ".codex-plugin/plugin.json",
        "benchmarks/current-score.json",
        "benchmarks/elo-suite.json",
        "benchmarks/elo_cases.py",
        "policy/policy-v1.json",
        "schemas/evolution",
        "scripts/generic_skill_launcher.py",
        "scripts/install_agent_skills.py",
        "skills/audit-design-system",
        "skills/build-with-design-system",
    ):
        _copy(relative, target)
    manifest_path = target / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    if third_skill:
        extra = target / "skills" / "private-extra"
        extra.mkdir()
        (extra / "SKILL.md").write_text("synthetic third skill\n", encoding="utf-8")
    _run("git", "init", "-q", cwd=target)
    _run("git", "config", "user.email", "guardian@example.invalid", cwd=target)
    _run("git", "config", "user.name", "Guardian Test", cwd=target)
    _run("git", "add", ".", cwd=target)
    _run("git", "commit", "-q", "-m", "synthetic target", cwd=target)
    return target


class WeightedEloTrustedBenchmarkReviewTest(unittest.TestCase):
    def test_benchmark_derives_clean_package_identity_and_seals_two_runs(self) -> None:
        from guardian_core.elo import benchmark_elo, verify_benchmark_result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            target = _make_target(root, "target")
            result = benchmark_elo(home, target)
            verified = verify_benchmark_result(home, result)
            self.assertEqual(verified["pluginVersion"], "0.2.0")
            self.assertEqual(verified["sourceCommit"], _run("git", "rev-parse", "HEAD", cwd=target))
            self.assertRegex(verified["packageDigest"], r"^[0-9a-f]{64}$")
            self.assertEqual(verified["overallStatus"], "complete")
            self.assertTrue(verified["cases"])
            for case in verified["cases"]:
                self.assertEqual(len(case["repetitions"]), 2)
                self.assertEqual(
                    [item["status"] for item in case["repetitions"]], ["passed", "passed"]
                )
            self.assertNotIn(str(target), json.dumps(verified))

            (target / "dirty.txt").write_text("uncommitted", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "clean committed"):
                benchmark_elo(home, target)

    def test_evaluate_rejects_caller_authored_claims_and_private_versions(self) -> None:
        from guardian_core.elo import benchmark_elo, evaluate_elo

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline", third_skill=True))
            candidate = benchmark_elo(home, _make_target(root, "candidate", version="0.2.1"))
            forged = {
                "schemaVersion": 1,
                "model": "guardian-weighted-elo-v1",
                "passedAchievementIds": ["synthetic-correctness-exact-identity"],
            }
            with self.assertRaises(ValueError):
                evaluate_elo(home, forged, candidate)
            self.assertEqual(evaluate_elo(home, baseline, candidate)["delta"], 20)

            private_target = _make_target(root, "private-version", version="0.3.0+Acme.Vimal")
            with self.assertRaisesRegex(ValueError, "public version"):
                benchmark_elo(home, private_target)

    def test_controlled_failure_is_guardian_regression_but_infrastructure_aborts(self) -> None:
        from guardian_core.elo import EloIntegrityError, benchmark_elo, evaluate_elo

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline"))
            failing = benchmark_elo(
                home, _make_target(root, "failing", version="0.2.1", third_skill=True)
            )
            result = evaluate_elo(home, baseline, failing)
            self.assertEqual(result["delta"], -20)
            self.assertTrue(result["confirmedRegressionIds"])

            broken = _make_target(root, "broken", version="0.2.2")
            (broken / "benchmarks" / "elo_cases.py").write_text("raise SystemExit(7)\n", encoding="utf-8")
            _run("git", "add", ".", cwd=broken)
            _run("git", "commit", "-q", "-m", "break harness", cwd=broken)
            with self.assertRaisesRegex(EloIntegrityError, "infrastructure"):
                benchmark_elo(home, broken)

    def test_suite_transition_is_additive_and_cases_are_immutable(self) -> None:
        from guardian_core.elo import EloIntegrityError, _public_suite, _validate_suite_transition

        previous, _ = _public_suite()
        for mutate in (
            lambda value: value["achievements"].pop(),
            lambda value: value["achievements"][0].__setitem__("category", "reliability"),
            lambda value: value["achievements"][0].__setitem__("weight", 0),
            lambda value: value["achievements"][0].__setitem__("caseDigest", "f" * 64),
        ):
            changed = copy.deepcopy(previous)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(EloIntegrityError):
                _validate_suite_transition(previous, changed)

        added = copy.deepcopy(previous)
        added["achievements"].append(
            {
                "achievementId": "synthetic-correctness-additive-review",
                "category": "correctness",
                "weight": 1,
                "caseFunction": "case_additive_review",
                "caseDigest": "a" * 64,
            }
        )
        with self.assertRaisesRegex(EloIntegrityError, "version"):
            _validate_suite_transition(previous, added)
        added["suiteVersion"] += 1
        _validate_suite_transition(previous, added)

    def test_semantically_false_authority_valid_entry_is_rejected(self) -> None:
        from guardian_core.authority import authority_seal
        from guardian_core.canonical import atomic_write_json, read_canonical_json, sha256_digest
        from guardian_core.elo import benchmark_elo, evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline", third_skill=True))
            candidate = benchmark_elo(home, _make_target(root, "candidate", version="0.2.1"))
            evaluate_elo(home, baseline, candidate)
            history_path = next((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
            entry = read_canonical_json(history_path)
            entry["categoryDeltas"]["correctness"] += 1
            entry["delta"] += 1
            entry["score"] += 1
            digest_payload = {
                key: value for key, value in entry.items() if key not in {"entryDigest", "authoritySeal"}
            }
            entry["entryDigest"] = sha256_digest(digest_payload)
            unsigned = {key: value for key, value in entry.items() if key != "authoritySeal"}
            entry["authoritySeal"] = authority_seal(home, "elo-ledger:v2", unsigned)
            forged_path = history_path.with_name(
                f"{entry['sequence']:020d}-{entry['entryDigest']}.sealed.json"
            )
            history_path.unlink()
            atomic_write_json(forged_path, entry)
            head_path = home / "trust" / "elo-head.sealed.json"
            head = read_canonical_json(head_path)
            head["entryDigest"] = entry["entryDigest"]
            head["score"] = entry["score"]
            head_unsigned = {key: value for key, value in head.items() if key != "authoritySeal"}
            head["authoritySeal"] = authority_seal(home, "elo-head:v1", head_unsigned)
            atomic_write_json(head_path, head)
            with self.assertRaisesRegex(ValueError, "recomputed"):
                read_elo_state(home)

    def test_separate_head_detects_suffix_whole_history_and_rollback(self) -> None:
        from guardian_core.elo import benchmark_elo, evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline", third_skill=True))
            candidate = benchmark_elo(home, _make_target(root, "candidate", version="0.2.1"))
            evaluate_elo(home, baseline, candidate)
            head_path = home / "trust" / "elo-head.sealed.json"
            evaluate_elo(home, baseline, candidate)
            history = sorted((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
            history[-1].unlink()
            with self.assertRaises(ValueError):
                read_elo_state(home)
            history[-2].unlink()
            with self.assertRaises(ValueError):
                read_elo_state(home)

            # Restore history in a fresh home, then prove an older valid head is rejected.
            other = root / "other-home"
            _provision(other)
            baseline2 = benchmark_elo(other, _make_target(root, "baseline2", third_skill=True))
            candidate2 = benchmark_elo(other, _make_target(root, "candidate2", version="0.2.1"))
            evaluate_elo(other, baseline2, candidate2)
            old_head = (other / "trust" / "elo-head.sealed.json").read_bytes()
            evaluate_elo(other, baseline2, candidate2)
            (other / "trust" / "elo-head.sealed.json").write_bytes(old_head)
            with self.assertRaises(ValueError):
                read_elo_state(other)

    def test_nonce_lock_serializes_two_writers_and_detects_replacement(self) -> None:
        from guardian_core.elo import benchmark_elo, evaluate_elo, read_elo_state
        from guardian_core.storage import transaction_lock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline", third_skill=True))
            candidate = benchmark_elo(home, _make_target(root, "candidate", version="0.2.1"))
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: evaluate_elo(home, baseline, candidate), range(2)))
            self.assertEqual(read_elo_state(home)["sequence"], 2)
            self.assertEqual(sorted(item["delta"] for item in results), [0, 20])

            lock_path = home / "evolution" / "elo" / "replacement.lock"
            with self.assertRaisesRegex(OSError, "changed before release"):
                with transaction_lock(home, lock_path, purpose="elo-review"):
                    lock_path.write_bytes(b"guardian-elo-transaction-v1\n")


if __name__ == "__main__":
    unittest.main()

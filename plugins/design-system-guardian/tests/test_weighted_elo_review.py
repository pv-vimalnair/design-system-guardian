from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

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
    from scripts.install_agent_skills import PACKAGE_ENTRIES

    for relative in PACKAGE_ENTRIES:
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


def _synthetic_identity(target: Path) -> dict[str, str]:
    from guardian_core.elo import EloIntegrityError

    version = json.loads((target / ".codex-plugin" / "plugin.json").read_text("utf-8"))["version"]
    identities = {
        "0.2.0": ("05f736facf2187af638cf0ea6cb3897c77711c06", "a1ed3e786c565bb8e75e5cf207b9c3bd99e631bd", "03461d79d04b5ab807476e0851d4a2b0570774ae4ad85800c713355aafd58fdd"),
        "0.2.1": ("1" * 40, "2" * 40, "3" * 64),
        "0.2.2": ("4" * 40, "5" * 40, "6" * 64),
    }
    if version not in identities:
        raise EloIntegrityError("Synthetic target is not a plain public version.")
    commit, tree, package = identities[version]
    return {
        "canonicalRepository": "pv-vimalnair/design-system-guardian",
        "pluginVersion": version,
        "sourceCommit": commit,
        "sourceTree": tree,
        "packageDigest": package,
    }


class WeightedEloTrustedBenchmarkReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity_patch = patch("guardian_core.elo._target_identity", side_effect=_synthetic_identity)
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
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
            self.assertEqual(verified["sourceCommit"], "05f736facf2187af638cf0ea6cb3897c77711c06")
            self.assertRegex(verified["packageDigest"], r"^[0-9a-f]{64}$")
            self.assertEqual(verified["overallStatus"], "complete")
            self.assertTrue(verified["cases"])
            for case in verified["cases"]:
                self.assertEqual(len(case["repetitions"]), 2)
                statuses = [item["status"] for item in case["repetitions"]]
                self.assertEqual(statuses[0], statuses[1])
                self.assertIn(statuses[0], {"passed", "assertion_failed"})
            self.assertNotIn(str(target), json.dumps(verified))



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
            result = evaluate_elo(home, baseline, candidate)
            self.assertEqual(result["delta"], 0)
            self.assertIn(
                "synthetic-portability-basic-host",
                result["newAchievementIds"],
            )

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
            self.assertEqual(result["delta"], 0)
            self.assertIn(
                "synthetic-portability-basic-host",
                result["confirmedRegressionIds"],
            )

            broken = _make_target(root, "broken", version="0.2.2")
            failed_process = subprocess.CompletedProcess([], 7, stdout=b"", stderr=b"")
            with patch("guardian_core.elo.subprocess.run", return_value=failed_process):
                with self.assertRaisesRegex(EloIntegrityError, "infrastructure"):
                    benchmark_elo(home, broken)

    def test_suite_transition_is_additive_and_cases_are_immutable(self) -> None:
        from guardian_core.elo import EloIntegrityError, _public_suite, _validate_suite_transition

        previous, _ = _public_suite()
        for mutate in (
            lambda value: value["achievements"].pop(),
            lambda value: value["achievements"][0].__setitem__("category", "reliability"),
            lambda value: value["achievements"][0].__setitem__("weight", 0),
            lambda value: value["achievements"][0].__setitem__("caseFunction", "case_changed"),
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
                "caseModuleId": previous["caseModules"][0]["moduleId"],
                "caseFunction": "case_additive_review",
                "workerDigest": previous["caseModules"][0]["workerDigest"],
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
            candidate_next = benchmark_elo(
                home, _make_target(root, "candidate-next", version="0.2.2")
            )
            evaluate_elo(home, candidate, candidate_next)
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
            candidate3 = benchmark_elo(
                other, _make_target(root, "candidate3", version="0.2.2")
            )
            evaluate_elo(other, candidate2, candidate3)
            (other / "trust" / "elo-head.sealed.json").write_bytes(old_head)
            with self.assertRaises(ValueError):
                read_elo_state(other)

    def test_legacy_migration_recovers_strict_partial_anchor_writes(self) -> None:
        from guardian_core import policy
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import read_elo_state

        anchor_names = (
            "elo-enrollment.sealed.json",
            "elo-ledger-init.sealed.json",
            "elo-head.sealed.json",
        )
        legacy_names = (
            "catalog-authority-ed25519.binding.json",
            "catalog-authority-ed25519.pem",
            "policy-v1.json",
            "policy-v1.sha256",
            "snapshot-authority-v1.key",
        )
        for interrupted_name in anchor_names:
            with (
                self.subTest(interrupted_name=interrupted_name),
                tempfile.TemporaryDirectory() as directory,
            ):
                home = Path(directory) / "home"
                _provision(home)
                trust = home / "trust"
                for name in anchor_names:
                    (trust / name).unlink()
                legacy_before = {
                    name: (trust / name).read_bytes() for name in legacy_names
                }

                self.assertTrue(policy.migrate_legacy_elo_genesis(home))
                original_ledger_id = read_canonical_json(
                    trust / "elo-enrollment.sealed.json"
                )["ledgerId"]
                interrupted_index = anchor_names.index(interrupted_name)
                for later_name in anchor_names[interrupted_index + 1 :]:
                    (trust / later_name).unlink()
                interrupted_path = trust / interrupted_name
                complete_bytes = interrupted_path.read_bytes()
                interrupted_path.write_bytes(
                    complete_bytes[: len(complete_bytes) // 2]
                )

                self.assertTrue(policy.migrate_legacy_elo_genesis(home))
                self.assertEqual(read_elo_state(home)["sequence"], 0)
                recovered_enrollment = read_canonical_json(
                    trust / "elo-enrollment.sealed.json"
                )
                self.assertEqual(recovered_enrollment["ledgerId"], original_ledger_id)
                for name in anchor_names:
                    self.assertIsInstance(read_canonical_json(trust / name), dict)
                self.assertEqual(
                    {name: (trust / name).read_bytes() for name in legacy_names},
                    legacy_before,
                )
                self.assertFalse(policy.migrate_legacy_elo_genesis(home))

    def test_legacy_migration_rejects_sealed_nondeterministic_enrollment(self) -> None:
        from guardian_core import policy
        from guardian_core.canonical import atomic_write_json
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.paths import GuardianPaths

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            trust = home / "trust"
            anchor_names = (
                "elo-enrollment.sealed.json",
                "elo-ledger-init.sealed.json",
                "elo-head.sealed.json",
            )
            for name in anchor_names:
                (trust / name).unlink()
            deterministic_id = policy._legacy_elo_ledger_id(GuardianPaths(home))
            first_digit = "0" if deterministic_id[0] != "0" else "1"
            arbitrary_id = first_digit + deterministic_id[1:]
            authority_key = (trust / "snapshot-authority-v1.key").read_bytes()
            marker, head = policy._elo_anchors_with_key(authority_key, arbitrary_id)
            enrollment = policy._elo_enrollment_with_key(
                authority_key,
                arbitrary_id,
                enrolled_from="legacy-0.2-migration",
            )
            for name, value in zip(
                anchor_names,
                (enrollment, marker, head),
                strict=True,
            ):
                atomic_write_json(trust / name, value)
            before = {path.name: path.read_bytes() for path in trust.iterdir()}

            with self.assertRaisesRegex(PolicyIntegrityError, "deterministic"):
                policy.migrate_legacy_elo_genesis(home)

            self.assertEqual(
                {path.name: path.read_bytes() for path in trust.iterdir()},
                before,
            )

    def test_legacy_migration_rejects_unknown_trust_entries_in_every_state(
        self,
    ) -> None:
        from guardian_core import policy
        from guardian_core.errors import PolicyIntegrityError

        anchor_names = (
            "elo-enrollment.sealed.json",
            "elo-ledger-init.sealed.json",
            "elo-head.sealed.json",
        )
        states = {
            "five-file": 0,
            "enrollment": 1,
            "marker": 2,
            "complete": 3,
        }
        for state, retained_anchors in states.items():
            with (
                self.subTest(state=state),
                tempfile.TemporaryDirectory() as directory,
            ):
                home = Path(directory) / "home"
                _provision(home)
                trust = home / "trust"
                for name in anchor_names:
                    (trust / name).unlink()
                if retained_anchors:
                    self.assertTrue(policy.migrate_legacy_elo_genesis(home))
                    for name in anchor_names[retained_anchors:]:
                        (trust / name).unlink()
                (trust / "unexpected.txt").write_text(
                    "unexpected", encoding="utf-8"
                )
                before = {
                    path.name: path.read_bytes() for path in trust.iterdir()
                }

                with self.assertRaisesRegex(PolicyIntegrityError, "exact|unknown"):
                    policy.migrate_legacy_elo_genesis(home)

                self.assertEqual(
                    {path.name: path.read_bytes() for path in trust.iterdir()},
                    before,
                )

    def test_nonce_lock_serializes_two_writers_and_detects_replacement(self) -> None:
        from guardian_core.elo import benchmark_elo, evaluate_elo, read_elo_state
        from guardian_core.storage import transaction_lock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline = benchmark_elo(home, _make_target(root, "baseline", third_skill=True))
            candidate = benchmark_elo(home, _make_target(root, "candidate", version="0.2.1"))
            def attempt() -> object:
                try:
                    return evaluate_elo(home, baseline, candidate)
                except Exception as error:
                    return error

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: attempt(), range(2)))
            self.assertEqual(read_elo_state(home)["sequence"], 1)
            self.assertEqual(sum(isinstance(item, Exception) for item in results), 0)
            self.assertEqual(results[0], results[1])

            lock_path = home / "evolution" / "elo" / "replacement.lock"
            with self.assertRaisesRegex(OSError, "changed before release"):
                with transaction_lock(home, lock_path, purpose="elo-review"):
                    lock_path.write_bytes(b"guardian-elo-transaction-v1\n")


if __name__ == "__main__":
    unittest.main()

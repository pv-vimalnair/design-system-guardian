from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_weighted_elo_rereview import _provision, _sealed_pair


ROOT = Path(__file__).resolve().parents[1]


LEGACY_TRUST_FILES = {
    "catalog-authority-ed25519.binding.json",
    "catalog-authority-ed25519.pem",
    "policy-v1.json",
    "policy-v1.sha256",
    "snapshot-authority-v1.key",
}


def _different_candidate(home: Path, candidate: dict) -> dict:
    from guardian_core.elo import (
        _public_suite,
        _repetition_evidence,
        _seal_result,
    )

    suite, definitions = _public_suite()
    modules = {item["moduleId"]: item for item in suite["caseModules"]}
    unsigned = copy.deepcopy(candidate)
    unsigned.pop("authoritySeal")
    case = unsigned["cases"][0]
    definition = definitions[case["achievementId"]]
    module = modules[definition["caseModuleId"]]
    for repetition in case["repetitions"]:
        repetition["status"] = "assertion_failed"
        repetition["evidenceDigest"] = _repetition_evidence(
            definition,
            module,
            unsigned["conditionDigest"],
            unsigned["packageDigest"],
            repetition["repetition"],
            "assertion_failed",
        )
    return _seal_result(home, unsigned)


class EloUpgradeRecoveryTest(unittest.TestCase):
    def test_advisory_lock_rejects_hard_link_without_mutating_outside_file(self) -> None:
        from guardian_core.policy import ELO_ENROLLMENT_NAME
        from guardian_core.storage import advisory_transaction_lock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            outside = root / "outside.lock"
            outside.write_bytes(b"")
            lock = home / "trust" / ELO_ENROLLMENT_NAME
            lock.unlink()
            os.link(outside, lock)

            with self.assertRaisesRegex(OSError, "single-link"):
                with advisory_transaction_lock(
                    home, lock, purpose="guardian-elo-lock-v3"
                ):
                    self.fail("A hard-linked enrollment receipt must never be locked.")

            self.assertEqual(outside.read_bytes(), b"")
            self.assertEqual(lock.read_bytes(), b"")

    def test_advisory_lock_requires_an_existing_file_without_creating_one(self) -> None:
        from guardian_core.storage import advisory_transaction_lock

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            missing = home / "trust" / "missing.sealed.json"
            missing.parent.mkdir(parents=True)

            with self.assertRaises(FileNotFoundError):
                with advisory_transaction_lock(
                    home, missing, purpose="guardian-elo-lock-v3"
                ):
                    self.fail("An advisory lock must never create its target.")

            self.assertFalse(missing.exists())

    def test_evaluation_locks_enrollment_without_creating_a_lock_sentinel(self) -> None:
        from guardian_core.elo import evaluate_elo
        from guardian_core.policy import ELO_ENROLLMENT_NAME
        from guardian_core.storage import advisory_transaction_lock as real_lock

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            lock_paths: list[Path] = []

            def record_lock(
                lock_home: Path, lock_path: Path, **options: object
            ) -> object:
                lock_paths.append(lock_path)
                return real_lock(lock_home, lock_path, **options)

            with patch(
                "guardian_core.elo.advisory_transaction_lock",
                side_effect=record_lock,
            ):
                evaluate_elo(home, baseline, candidate)

            self.assertEqual(
                lock_paths,
                [home / "trust" / ELO_ENROLLMENT_NAME],
            )
            self.assertFalse(
                (home / "evolution" / "elo" / "transaction.lock").exists()
            )

    def test_zero_byte_enrollment_fails_without_mutation_or_lock_artifact(self) -> None:
        from guardian_core.elo import evaluate_elo
        from guardian_core.policy import ELO_ENROLLMENT_NAME

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            enrollment = home / "trust" / ELO_ENROLLMENT_NAME
            enrollment.write_bytes(b"")

            with self.assertRaises((OSError, ValueError)):
                evaluate_elo(home, baseline, candidate)

            self.assertEqual(enrollment.read_bytes(), b"")
            self.assertFalse(
                (home / "evolution" / "elo" / "transaction.lock").exists()
            )

    def test_cli_rejects_elo_migration_for_fresh_install(self) -> None:
        from guardian_core.cli import main
        from guardian_core.elo import read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            error_output = io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), patch(
                "sys.stderr", error_output
            ):
                self.assertEqual(main(["elo", "migrate"]), 2)

            result = json.loads(error_output.getvalue())
            self.assertEqual(result["status"], "invalid")
            self.assertRegex(result["message"], "not a legacy")
            state = read_elo_state(home)
            self.assertEqual(state["score"], 1)
            self.assertEqual(state["sequence"], 0)

    def test_explicit_legacy_migration_preserves_the_five_pre_elo_trust_files(self) -> None:
        from guardian_core import policy
        from guardian_core.elo import read_elo_state

        self.assertTrue(
            hasattr(policy, "migrate_legacy_elo_genesis"),
            "Guardian needs an explicit supported 0.2 Elo migration API.",
        )
        migrate = policy.migrate_legacy_elo_genesis
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            trust = home / "trust"
            for name in (
                "elo-enrollment.sealed.json",
                "elo-ledger-init.sealed.json",
                "elo-head.sealed.json",
            ):
                (trust / name).unlink(missing_ok=True)
            self.assertEqual({path.name for path in trust.iterdir()}, LEGACY_TRUST_FILES)
            before = {path.name: path.read_bytes() for path in trust.iterdir()}

            from guardian_core.cli import main

            output = io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), patch(
                "sys.stdout", output
            ):
                self.assertEqual(main(["elo", "migrate"]), 0)
            cli_result = json.loads(output.getvalue())
            self.assertTrue(cli_result["changed"])
            self.assertTrue(cli_result["newLedger"])
            self.assertTrue(cli_result["continuityReset"])
            self.assertFalse(cli_result["continuityFromPriorLedgerProven"])
            self.assertRegex(cli_result["ledgerId"], r"^[0-9a-f]{64}$")
            self.assertEqual(cli_result["score"], 1)
            self.assertEqual(cli_result["sequence"], 0)
            self.assertEqual(
                {name: (trust / name).read_bytes() for name in LEGACY_TRUST_FILES},
                before,
            )
            migrated = {path.name: path.read_bytes() for path in trust.iterdir()}
            self.assertEqual(read_elo_state(home)["score"], 1)
            self.assertEqual(read_elo_state(home)["sequence"], 0)
            repeated_output = io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), patch(
                "sys.stdout", repeated_output
            ):
                self.assertEqual(main(["elo", "migrate"]), 0)
            repeated_result = json.loads(repeated_output.getvalue())
            self.assertFalse(repeated_result["changed"])
            self.assertTrue(repeated_result["newLedger"])
            self.assertTrue(repeated_result["continuityReset"])
            self.assertFalse(repeated_result["continuityFromPriorLedgerProven"])
            self.assertEqual(repeated_result["ledgerId"], cli_result["ledgerId"])
            self.assertFalse(migrate(home))
            self.assertEqual(
                {path.name: path.read_bytes() for path in trust.iterdir()}, migrated
            )

    def test_legacy_migration_refuses_deletion_from_an_enrolled_fresh_home(self) -> None:
        from guardian_core import policy
        from guardian_core.errors import PolicyIntegrityError

        self.assertTrue(hasattr(policy, "migrate_legacy_elo_genesis"))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            trust = home / "trust"
            receipt = trust / "elo-enrollment.sealed.json"
            self.assertTrue(receipt.is_file())
            (trust / "elo-ledger-init.sealed.json").unlink()
            (trust / "elo-head.sealed.json").unlink()

            with self.assertRaisesRegex(PolicyIntegrityError, "deletion"):
                policy.migrate_legacy_elo_genesis(home)
            self.assertFalse((trust / "elo-ledger-init.sealed.json").exists())
            self.assertFalse((trust / "elo-head.sealed.json").exists())

    def test_legacy_migration_refuses_a_nonempty_ledger_even_if_all_anchors_are_deleted(self) -> None:
        from guardian_core import policy
        from guardian_core.elo import evaluate_elo
        from guardian_core.errors import PolicyIntegrityError

        self.assertTrue(hasattr(policy, "migrate_legacy_elo_genesis"))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            evaluate_elo(home, baseline, candidate)
            trust = home / "trust"
            for name in (
                "elo-enrollment.sealed.json",
                "elo-ledger-init.sealed.json",
                "elo-head.sealed.json",
            ):
                (trust / name).unlink()

            with self.assertRaisesRegex(PolicyIntegrityError, "ledger|deletion"):
                policy.migrate_legacy_elo_genesis(home)
            self.assertEqual(
                len(list((home / "evolution" / "elo" / "history").glob("*.sealed.json"))),
                1,
            )

    def test_cli_exposes_the_explicit_legacy_genesis_migration(self) -> None:
        from guardian_core.cli import build_parser

        parser = build_parser()
        command_action = next(
            action for action in parser._actions if getattr(action, "choices", None)
        )
        elo_parser = command_action.choices["elo"]
        elo_action = next(
            action for action in elo_parser._actions if getattr(action, "choices", None)
        )
        self.assertIn("migrate", elo_action.choices)
        self.assertIn("migrate", elo_parser.format_help())

    def test_failed_evaluation_on_exact_legacy_home_does_not_poison_migrate_or_show(self) -> None:
        from guardian_core.cli import main
        from guardian_core.elo import EloIntegrityError, evaluate_elo

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            trust = home / "trust"
            for name in (
                "elo-enrollment.sealed.json",
                "elo-ledger-init.sealed.json",
                "elo-head.sealed.json",
            ):
                (trust / name).unlink()
            self.assertEqual({path.name for path in trust.iterdir()}, LEGACY_TRUST_FILES)
            baseline, candidate = _sealed_pair(home)

            with self.assertRaisesRegex(EloIntegrityError, "migration"):
                evaluate_elo(home, baseline, candidate)
            self.assertFalse((home / "evolution" / "elo").exists())

            migrate_output = io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), patch(
                "sys.stdout", migrate_output
            ):
                self.assertEqual(main(["elo", "migrate"]), 0)
            migrated = json.loads(migrate_output.getvalue())
            self.assertTrue(migrated["newLedger"])
            self.assertTrue(migrated["continuityReset"])

            show_output = io.StringIO()
            with patch("guardian_core.cli.default_guardian_home", return_value=home), patch(
                "sys.stdout", show_output
            ):
                self.assertEqual(main(["elo", "show"]), 0)
            shown = json.loads(show_output.getvalue())
            self.assertEqual(shown["score"], 1)
            self.assertEqual(shown["sequence"], 0)

    def test_killed_writer_releases_elo_lock_and_retry_recovers_exactly_once(self) -> None:
        from guardian_core.canonical import atomic_write_json
        from guardian_core.elo import evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            atomic_write_json(baseline_path, baseline)
            atomic_write_json(candidate_path, candidate)
            child = """import os,sys
from pathlib import Path
from guardian_core.canonical import read_canonical_json
import guardian_core.elo as elo
elo._write_head=lambda *_args,**_kwargs: os._exit(73)
elo.evaluate_elo(Path(sys.argv[1]),read_canonical_json(Path(sys.argv[2])),read_canonical_json(Path(sys.argv[3])))
"""
            killed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    child,
                    str(home),
                    str(baseline_path),
                    str(candidate_path),
                ],
                cwd=ROOT,
                check=False,
                timeout=30,
            )
            self.assertEqual(killed.returncode, 73)
            history = home / "evolution" / "elo" / "history"
            self.assertEqual(len(list(history.glob("*.sealed.json"))), 1)

            recovered = evaluate_elo(home, baseline, candidate)
            self.assertEqual(recovered["sequence"], 1)
            self.assertEqual(len(list(history.glob("*.sealed.json"))), 1)
            self.assertEqual(read_elo_state(home)["entryDigest"], recovered["entryDigest"])

    def test_migration_docs_disclose_total_erasure_and_new_ledger_semantics(self) -> None:
        updating = (ROOT / "docs" / "UPDATING.md").read_text("utf-8").lower()
        self.assertIn("total local erasure", updating)
        self.assertIn("indistinguishable", updating)
        self.assertIn("new local ledger", updating)
        self.assertIn("continuityreset", updating)
        self.assertIn("newledger", updating)
        self.assertIn("continuityfrompriorledgerproven", updating)
    def test_retry_after_interrupted_head_write_is_exactly_once_and_idempotent(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            with patch(
                "guardian_core.elo._write_head", side_effect=OSError("interrupted")
            ):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    evaluate_elo(home, baseline, candidate)

            history = home / "evolution" / "elo" / "history"
            self.assertEqual(len(list(history.glob("*.sealed.json"))), 1)
            recovered = evaluate_elo(home, baseline, candidate)
            repeated = evaluate_elo(home, baseline, candidate)
            self.assertEqual(repeated, recovered)
            self.assertEqual(recovered["sequence"], 1)
            self.assertEqual(len(list(history.glob("*.sealed.json"))), 1)
            head = read_canonical_json(home / "trust" / "elo-head.sealed.json")
            self.assertEqual(head["sequence"], 1)
            self.assertEqual(head["entryDigest"], recovered["entryDigest"])
            self.assertEqual(read_elo_state(home)["sequence"], 1)

    def test_different_retry_recovers_the_persisted_entry_then_requires_a_rerun(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import EloIntegrityError, evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            different = _different_candidate(home, candidate)
            with patch(
                "guardian_core.elo._write_head", side_effect=OSError("interrupted")
            ):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    evaluate_elo(home, baseline, candidate)

            with self.assertRaisesRegex(EloIntegrityError, "recovered.*rerun"):
                evaluate_elo(home, baseline, different)

            history = home / "evolution" / "elo" / "history"
            entries = list(history.glob("*.sealed.json"))
            self.assertEqual(len(entries), 1)
            entry = read_canonical_json(entries[0])
            head = read_canonical_json(home / "trust" / "elo-head.sealed.json")
            self.assertEqual(head["entryDigest"], entry["entryDigest"])
            self.assertEqual(read_elo_state(home)["sequence"], 1)


if __name__ == "__main__":
    unittest.main()

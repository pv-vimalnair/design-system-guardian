from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.guardian_test_support import catalog_authority_public_key_path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_COMMIT = "05f736facf2187af638cf0ea6cb3897c77711c06"
BOOTSTRAP_PACKAGE = "03461d79d04b5ab807476e0851d4a2b0570774ae4ad85800c713355aafd58fdd"


def _provision(home: Path) -> None:
    from guardian_core.policy import install_policy_anchor

    install_policy_anchor(
        home, catalog_authority_public_key=catalog_authority_public_key_path(home)
    )


def _materialize_bootstrap(parent: Path) -> Path:
    repository = ROOT.parents[1]
    target = parent / "bootstrap"
    target.mkdir()
    prefix = "plugins/design-system-guardian/"
    raw = subprocess.check_output(
        ["git", "ls-tree", "-rz", BOOTSTRAP_COMMIT, "--", prefix], cwd=repository
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
            subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository)
        )
    return target


def _package_bytes_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file())):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()

def _sealed_pair(home: Path) -> tuple[dict, dict]:
    from guardian_core.canonical import sha256_digest
    from guardian_core.elo import (
        ELO_MODEL,
        _public_suite,
        _repetition_evidence,
        _runtime_digest,
        _seal_result,
    )
    from guardian_core.policy import verify_policy_anchor

    suite, _ = _public_suite()
    suite_digest = sha256_digest(suite)
    policy_digest = verify_policy_anchor(home)
    runtime_digest = _runtime_digest()
    condition_digest = sha256_digest(
        {
            "model": ELO_MODEL,
            "policyDigest": policy_digest,
            "runtimeDigest": runtime_digest,
            "suiteDigest": suite_digest,
        }
    )
    modules = {item["moduleId"]: item for item in suite["caseModules"]}
    identities = (
        {
            "canonicalRepository": "pv-vimalnair/design-system-guardian",
            "pluginVersion": "0.2.0",
            "sourceCommit": BOOTSTRAP_COMMIT,
            "sourceTree": "a1ed3e786c565bb8e75e5cf207b9c3bd99e631bd",
            "packageDigest": BOOTSTRAP_PACKAGE,
        },
        {
            "canonicalRepository": "pv-vimalnair/design-system-guardian",
            "pluginVersion": "0.2.1",
            "sourceCommit": "1" * 40,
            "sourceTree": "2" * 40,
            "packageDigest": "3" * 64,
        },
    )
    results = []
    for identity in identities:
        cases = []
        for definition in suite["achievements"]:
            module = modules[definition["caseModuleId"]]
            repetitions = []
            for repetition in (1, 2):
                repetitions.append(
                    {
                        "repetition": repetition,
                        "status": "passed",
                        "evidenceDigest": _repetition_evidence(
                            definition,
                            module,
                            condition_digest,
                            identity["packageDigest"],
                            repetition,
                            "passed",
                        ),
                    }
                )
            cases.append(
                {
                    "achievementId": definition["achievementId"],
                    "caseModuleId": definition["caseModuleId"],
                    "moduleDigest": module["moduleDigest"],
                    "caseFunction": definition["caseFunction"],
                    "workerDigest": definition["workerDigest"],
                    "repetitions": repetitions,
                }
            )
        results.append(
            _seal_result(
                home,
                {
                    "schemaVersion": 2,
                    "model": ELO_MODEL,
                    "resultAuthority": "local-guardian-v1",
                    "overallStatus": "complete",
                    "suiteDigest": suite_digest,
                    "policyDigest": policy_digest,
                    "runtimeDigest": runtime_digest,
                    "conditionDigest": condition_digest,
                    "pluginName": "design-system-guardian",
                    **identity,
                    "cases": cases,
                },
            )
        )
    return results[0], results[1]


class WeightedEloSecondReviewTest(unittest.TestCase):
    def test_new_install_has_sealed_fresh_genesis(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import _head_path, _marker_path, _verify_head, _verify_marker, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            marker = _verify_marker(home, read_canonical_json(_marker_path(home)))
            head = _verify_head(home, read_canonical_json(_head_path(home)))
            self.assertEqual(head["ledgerId"], marker["ledgerId"])
            self.assertEqual(
                {key: head[key] for key in ("sequence", "entryDigest", "score", "suiteDigest")},
                {"sequence": 0, "entryDigest": None, "score": 1, "suiteDigest": None},
            )
            self.assertEqual(read_elo_state(home)["sequence"], 0)
            self.assertFalse((home / "evolution" / "elo" / "history").exists())

    def test_first_append_advances_preseeded_genesis(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import _head_path, _marker_path, evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            marker_before = read_canonical_json(_marker_path(home))
            baseline, candidate = _sealed_pair(home)
            result = evaluate_elo(home, baseline, candidate)
            marker_after = read_canonical_json(_marker_path(home))
            head = read_canonical_json(_head_path(home))
            self.assertEqual(marker_after, marker_before)
            self.assertEqual(result["ledgerId"], marker_before["ledgerId"])
            self.assertEqual(head["ledgerId"], marker_before["ledgerId"])
            self.assertEqual(head["sequence"], 1)
            self.assertEqual(read_elo_state(home)["sequence"], 1)

    def test_simultaneous_all_anchor_deletion_never_reseeds(self) -> None:
        from guardian_core.elo import EloIntegrityError, _head_path, _marker_path, evaluate_elo, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            baseline, candidate = _sealed_pair(home)
            evaluate_elo(home, baseline, candidate)
            marker = _marker_path(home)
            head = _head_path(home)
            history = next((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
            marker.unlink()
            head.unlink()
            history.unlink()
            with self.assertRaisesRegex(EloIntegrityError, "migration"):
                read_elo_state(home)
            with self.assertRaisesRegex(EloIntegrityError, "migration"):
                evaluate_elo(home, baseline, candidate)
            self.assertFalse(marker.exists())
            self.assertFalse(head.exists())
            self.assertFalse(any((home / "evolution" / "elo" / "history").iterdir()))

    def test_legacy_trust_without_elo_anchors_requires_manual_migration(self) -> None:
        from guardian_core.elo import EloIntegrityError, _head_path, _marker_path, read_elo_state
        from guardian_core.policy import install_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            _provision(home)
            _marker_path(home).unlink()
            _head_path(home).unlink()
            repeated = install_policy_anchor(
                home,
                catalog_authority_public_key=home / "catalog-authority-input.pem",
            )
            self.assertFalse(repeated.created)
            with self.assertRaisesRegex(EloIntegrityError, "migration"):
                read_elo_state(home)
            self.assertFalse(_marker_path(home).exists())
            self.assertFalse(_head_path(home).exists())

    def test_current_score_pins_authenticated_public_bootstrap(self) -> None:
        current = json.loads((ROOT / "benchmarks" / "current-score.json").read_text("utf-8"))
        self.assertEqual(
            current["bootstrapCandidate"],
            {
                "canonicalRepository": "pv-vimalnair/design-system-guardian",
                "pluginVersion": "0.2.0",
                "sourceCommit": BOOTSTRAP_COMMIT,
                "sourceTree": "a1ed3e786c565bb8e75e5cf207b9c3bd99e631bd",
                "packageDigest": BOOTSTRAP_PACKAGE,
            },
        )

    def test_suite_freezes_full_modules_and_worker_semantics(self) -> None:
        from guardian_core.elo import EloIntegrityError, _public_suite, _validate_suite_transition

        suite, _ = _public_suite()
        module = suite["caseModules"][0]
        self.assertEqual(
            hashlib.sha256((ROOT / module["path"]).read_bytes()).hexdigest(),
            module["moduleDigest"],
        )
        for field in ("moduleDigest", "path", "workerDigest"):
            changed = copy.deepcopy(suite)
            changed["caseModules"][0][field] = "f" * 64 if field != "path" else "x.py"
            with self.subTest(field=field), self.assertRaises(EloIntegrityError):
                _validate_suite_transition(suite, changed)
        changed = copy.deepcopy(suite)
        changed["achievements"][0]["caseModuleId"] = "other-module"
        with self.assertRaises(EloIntegrityError):
            _validate_suite_transition(suite, changed)

    def test_canonical_target_rejects_lookalike_redirect_and_path_git_forgery(self) -> None:
        from guardian_core.elo import EloIntegrityError, _authenticate_canonical_target, _github_json

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "file.txt").write_bytes(b"lookalike")
            commit = "1" * 40
            tree = "2" * 40
            responses = {
                f"commits/{commit}": {"sha": commit, "tree": {"sha": tree}},
                f"git/trees/{tree}?recursive=1": {
                    "sha": tree,
                    "truncated": False,
                    "tree": [{"path": "plugins/design-system-guardian/file.txt", "mode": "100644", "type": "blob", "sha": "0" * 40}],
                },
            }
            fetch = lambda suffix: responses[suffix]
            with self.assertRaises(EloIntegrityError):
                _authenticate_canonical_target(target, commit, fetch=fetch)
            with self.assertRaises(EloIntegrityError):
                _authenticate_canonical_target(target, "3" * 40, fetch=fetch)

            truncated = copy.deepcopy(responses)
            truncated[f"git/trees/{tree}?recursive=1"]["truncated"] = True
            with self.assertRaisesRegex(EloIntegrityError, "truncated"):
                _authenticate_canonical_target(target, commit, fetch=lambda suffix: truncated[suffix])

            class RedirectedResponse:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def geturl(self) -> str:
                    return "https://lookalike.invalid/redirect"

                def read(self, _limit: int) -> bytes:
                    return b"{}"

            class RedirectedOpener:
                def open(self, *_args, **_kwargs):
                    return RedirectedResponse()

            with patch(
                "guardian_core.elo.urllib.request.build_opener",
                return_value=RedirectedOpener(),
            ), self.assertRaisesRegex(EloIntegrityError, "identity"):
                _github_json(f"commits/{commit}")

    def test_continuity_requires_bootstrap_then_previous_candidate_and_newer_version(self) -> None:
        from guardian_core.elo import EloIntegrityError, _validate_continuity

        current = json.loads((ROOT / "benchmarks" / "current-score.json").read_text("utf-8"))
        baseline = dict(current["bootstrapCandidate"])
        candidate = {**baseline, "pluginVersion": "0.2.1", "sourceCommit": "1" * 40, "packageDigest": "2" * 64}
        _validate_continuity(None, current, baseline, candidate)
        with self.assertRaises(EloIntegrityError):
            _validate_continuity(None, current, candidate, baseline)
        previous = {"candidateResult": candidate}
        newer = {**candidate, "pluginVersion": "0.3.0", "sourceCommit": "3" * 40, "packageDigest": "4" * 64}
        _validate_continuity(previous, current, candidate, newer)
        with self.assertRaises(EloIntegrityError):
            _validate_continuity(previous, current, baseline, newer)
        with self.assertRaises(EloIntegrityError):
            _validate_continuity(previous, current, candidate, candidate)

    def test_marker_prevents_reset_when_any_local_anchor_remains(self) -> None:
        from guardian_core.elo import EloIntegrityError, _head_path, read_elo_state

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _provision(home)
            _head_path(home).unlink()
            with self.assertRaisesRegex(EloIntegrityError, "deletion"):
                read_elo_state(home)
    def test_additive_suite_runs_against_unchanged_baseline_and_anchors_deletions(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.elo import (
            _public_suite,
            _validate_suite,
            benchmark_elo,
            evaluate_elo,
            read_elo_state,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            _provision(home)
            baseline_target = _materialize_bootstrap(root)
            before = _package_bytes_digest(baseline_target)
            base_suite, _ = _public_suite()
            additive = copy.deepcopy(base_suite)
            additive["suiteVersion"] += 1
            module_path = ROOT / "benchmarks" / "elo_cases_v2.py"
            module_digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
            worker_digest = additive["caseModules"][0]["workerDigest"]
            additive["caseModules"].append(
                {
                    "moduleId": "guardian-public-cases-v2",
                    "path": "benchmarks/elo_cases_v2.py",
                    "moduleDigest": module_digest,
                    "workerDigest": worker_digest,
                }
            )
            additive["achievements"].append(
                {
                    "achievementId": "synthetic-correctness-additive-runtime",
                    "category": "correctness",
                    "weight": 1,
                    "caseModuleId": "guardian-public-cases-v2",
                    "caseFunction": "case_additive_elo_runtime",
                    "workerDigest": worker_digest,
                }
            )
            additive, by_id = _validate_suite(additive)
            baseline_identity = {
                "canonicalRepository": "pv-vimalnair/design-system-guardian",
                "pluginVersion": "0.2.0",
                "sourceCommit": BOOTSTRAP_COMMIT,
                "sourceTree": "a1ed3e786c565bb8e75e5cf207b9c3bd99e631bd",
                "packageDigest": BOOTSTRAP_PACKAGE,
            }
            candidate_identity = {
                "canonicalRepository": "pv-vimalnair/design-system-guardian",
                "pluginVersion": "0.2.1",
                "sourceCommit": "c" * 40,
                "sourceTree": "d" * 40,
                "packageDigest": "e" * 64,
            }

            def identity(target: Path) -> dict[str, str]:
                return baseline_identity if target.resolve() == baseline_target.resolve() else candidate_identity

            with patch("guardian_core.elo._public_suite", return_value=(additive, by_id)), patch(
                "guardian_core.elo._target_identity", side_effect=identity
            ):
                baseline = benchmark_elo(home, baseline_target)
                candidate = benchmark_elo(home, ROOT)
                baseline_case = baseline["cases"][-1]
                candidate_case = candidate["cases"][-1]
                self.assertEqual([item["status"] for item in baseline_case["repetitions"]], ["assertion_failed", "assertion_failed"])
                self.assertEqual([item["status"] for item in candidate_case["repetitions"]], ["passed", "passed"])
                result = evaluate_elo(home, baseline, candidate)
                self.assertIn("synthetic-correctness-additive-runtime", result["newAchievementIds"])
                result_schema = json.loads(
                    (ROOT / "schemas/evolution/elo-benchmark-result.schema.json").read_text("utf-8")
                )
                entry_schema = json.loads(
                    (ROOT / "schemas/evolution/elo-ledger-entry.schema.json").read_text("utf-8")
                )
                Draft202012Validator(result_schema).validate(baseline)
                Draft202012Validator(result_schema).validate(candidate)
                entry_path = next((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
                entry = read_canonical_json(entry_path)
                registry = Registry().with_resource(
                    result_schema["$id"], Resource.from_contents(result_schema)
                )
                Draft202012Validator(entry_schema, registry=registry).validate(entry)
                self.assertEqual(_package_bytes_digest(baseline_target), before)

                marker = home / "trust" / "elo-ledger-init.sealed.json"
                head = home / "trust" / "elo-head.sealed.json"
                history = next((home / "evolution" / "elo" / "history").glob("*.sealed.json"))
                for deleted in (marker, head, history):
                    payload = deleted.read_bytes()
                    deleted.unlink()
                    with self.subTest(deleted=deleted.name), self.assertRaises(ValueError):
                        read_elo_state(home)
                    deleted.write_bytes(payload)
                self.assertEqual(read_elo_state(home)["sequence"], 1)
    def test_arithmetic_caps_half_up_and_one_time_progression_are_explicit(self) -> None:
        from guardian_core.elo import ELO_WEIGHTS, _derive_evaluation, _public_suite, _round_half_up

        self.assertEqual(_round_half_up(1, 2), 1)
        self.assertEqual(ELO_WEIGHTS, {"correctness": 80, "reliability": 40, "coverage_usefulness": 30, "safety_privacy_integrity": 30, "portability_usability_performance": 20})
        suite, _ = _public_suite()
        cases = lambda status: [{"achievementId": item["achievementId"], "repetitions": [{"repetition": 1, "status": status}, {"repetition": 2, "status": status}]} for item in suite["achievements"]]
        base = {"cases": cases("assertion_failed")}
        candidate = {"cases": cases("passed")}
        first = _derive_evaluation([], 1, suite, base, candidate)
        self.assertEqual(first["categoryDeltas"], ELO_WEIGHTS)
        second = _derive_evaluation(first["achievementIds"], first["score"], suite, base, candidate)
        self.assertEqual(second["delta"], 0)

    def test_actual_result_and_entry_validate_against_both_schemas(self) -> None:
        result_schema = json.loads((ROOT / "schemas/evolution/elo-benchmark-result.schema.json").read_text("utf-8"))
        entry_schema = json.loads((ROOT / "schemas/evolution/elo-ledger-entry.schema.json").read_text("utf-8"))
        Draft202012Validator.check_schema(result_schema)
        Draft202012Validator.check_schema(entry_schema)
        self.assertIn("canonicalRepository", result_schema["required"])
        self.assertIn("ledgerId", entry_schema["required"])


if __name__ == "__main__":
    unittest.main()

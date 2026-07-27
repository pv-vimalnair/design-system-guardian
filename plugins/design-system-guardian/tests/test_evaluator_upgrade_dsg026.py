from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from guardian_core.canonical import read_canonical_json
from guardian_core.paths import GuardianPaths

from tests.catalog_authority_test_support import attest_catalog

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile
from tests.test_rule_activation_dsg025 import (
    catalog_v2,
    machine_rule,
    signed_catalog_v2,
    tree_bytes,
)


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PLUGIN_ROOT / "schemas"

def schema_validator(name: str) -> Draft202012Validator:
    store = {
        payload["$id"]: payload
        for path in SCHEMA_ROOT.rglob("*.schema.json")
        for payload in [json.loads(path.read_text(encoding="utf-8"))]
        if "$id" in payload
    }
    schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        (schema_id, Resource.from_contents(payload))
        for schema_id, payload in store.items()
    )
    return Draft202012Validator(schema, registry=registry)


def judgment_rule() -> dict:
    return {
        "schemaVersion": 1,
        "ruleId": "button-primary.judgment",
        "class": "judgment",
        "statement": "Private design prose must not appear in inventory output.",
        "appliesTo": {"kind": "component", "identity": "button.primary"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "synthetic-rulebook",
        },
    }


def informative_rule() -> dict:
    return {
        "schemaVersion": 1,
        "ruleId": "button-primary.informative",
        "class": "informative",
        "statement": "Private informational prose.",
        "appliesTo": {"kind": "component", "identity": "button.primary"},
        "provenance": {
            "origin": "figma_description",
            "figma": {
                "fileKey": "private-figma-file",
                "nodeId": "99:1",
                "sourceVersion": "private-version",
            },
            "docRef": None,
        },
    }


def provision_rule_snapshot(
    home: Path,
    *,
    profile_id: str = "example-company",
    rules: list[dict] | None = None,
) -> tuple[dict, dict, dict]:
    from guardian_core.rule_activation import (
        apply_rule_activation,
        preview_rule_activation,
    )

    profile = sample_profile(profile_id)
    ingest_test_snapshot(home, profile, sample_catalog(profile_id), now=NOW, sequence=1)
    catalog_document = catalog_v2(
        rules=rules
        if rules is not None
        else [
            machine_rule(),
            machine_rule(
                "button-primary.forbidden-widget",
                predicate_type="forbidden_identity_in_scope",
                scope="widget_class",
            ),
            informative_rule(),
        ]
    )
    catalog_document["profileId"] = profile_id
    catalog = attest_catalog(catalog_document, profile, sequence=2, issued_at=NOW)
    with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
        preview = preview_rule_activation(
            home,
            profile_id=profile_id,
            catalog_document=catalog,
        )
        bundle = {
            "schemaVersion": 1,
            "profileId": profile_id,
            "catalog": catalog,
            "permission": {**preview["permissionBinding"], "granted": True},
        }
        applied = apply_rule_activation(home, bundle)
    return profile, applied["snapshot"], bundle


class EvaluatorUpgradeSchemaTest(unittest.TestCase):
    def test_checkpoint_one_schemas_are_strict_and_constants_are_exact(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.evaluator_upgrade import (
            EVALUATOR_CAPABILITY_MATRIX,
            EVALUATOR_CONTRACT,
            EVALUATOR_CONTRACT_DIGEST,
            PREVIOUS_EVALUATOR_ID,
            TARGET_EVALUATOR_ID,
        )

        expected = {
            "evaluator-upgrade-permission.schema.json",
            "evaluator-authorization-record.schema.json",
            "evaluator-authorization-pointer.schema.json",
            "rules-list.schema.json",
        }
        for name in expected:
            schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            self.assertFalse(schema["additionalProperties"], name)
            self.assertIn("schemaVersion", schema["required"], name)
        self.assertEqual(PREVIOUS_EVALUATOR_ID, "guardian-flutter-usage-rules-v1")
        self.assertEqual(TARGET_EVALUATOR_ID, "guardian-flutter-usage-rules-v2")
        self.assertEqual(EVALUATOR_CONTRACT_DIGEST, sha256_digest(EVALUATOR_CONTRACT))
        self.assertEqual(
            [item["predicate"] for item in EVALUATOR_CAPABILITY_MATRIX["predicates"]],
            [
                "forbidden_identity_in_scope",
                "max_instances_per_scope",
                "forbidden_nesting",
                "required_companion",
                "allowed_parents",
                "variant_context",
            ],
        )


class EvaluatorUpgradeFlowTest(unittest.TestCase):
    def test_preview_denial_apply_and_replay_are_zero_write_or_idempotent(self) -> None:
        from guardian_core.evaluator_upgrade import (
            EvaluatorUpgradeError,
            apply_evaluator_upgrade,
            load_evaluator_authorization,
            preview_evaluator_upgrade,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, snapshot, _ = provision_rule_snapshot(home)
            baseline = tree_bytes(home)
            self.assertIsNone(
                load_evaluator_authorization(home, profile["profileId"]),
                "The v0.3.5 permission must never authorize evaluator v2.",
            )
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = preview_evaluator_upgrade(home, profile_id=profile["profileId"])
            self.assertEqual(preview["status"], "permission_required")
            self.assertFalse(preview["localChangesPerformed"])
            self.assertEqual(preview["permissionBinding"]["ruleSnapshotId"], snapshot["snapshotId"])
            self.assertEqual(tree_bytes(home), baseline)

            denied = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "permission": {**preview["permissionBinding"], "granted": False},
            }
            with self.assertRaises(EvaluatorUpgradeError):
                apply_evaluator_upgrade(home, denied)
            self.assertEqual(tree_bytes(home), baseline)

            permitted = copy.deepcopy(denied)
            permitted["permission"]["granted"] = True
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                first = apply_evaluator_upgrade(home, permitted)
            self.assertTrue(first["changed"])
            record = load_evaluator_authorization(home, profile["profileId"])
            self.assertIsNotNone(record)
            self.assertEqual(record["evaluatorId"], "guardian-flutter-usage-rules-v2")
            schema_validator("evaluator-upgrade-permission.schema.json").validate(permitted)
            schema_validator("evaluator-authorization-record.schema.json").validate(record)
            pointer = read_canonical_json(
                GuardianPaths(home).current_evaluator_authorization(profile["profileId"])
            )
            schema_validator("evaluator-authorization-pointer.schema.json").validate(pointer)
            after = tree_bytes(home)
            replay = apply_evaluator_upgrade(home, permitted)
            self.assertFalse(replay["changed"])
            self.assertEqual(replay["authorization"], record)
            self.assertEqual(tree_bytes(home), after)

            from guardian_core.rule_activation import ingest_rule_snapshot

            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                ingest_rule_snapshot(home, profile, signed_catalog_v2(profile, sequence=3))
            self.assertEqual(
                load_evaluator_authorization(home, profile["profileId"])["authorizationDigest"],
                record["authorizationDigest"],
            )
            after_refresh = tree_bytes(home)

            divergent = copy.deepcopy(permitted)
            divergent["permission"]["rulesDigest"] = "0" * 64
            with self.assertRaises(EvaluatorUpgradeError):
                apply_evaluator_upgrade(home, divergent)
            self.assertEqual(tree_bytes(home), after_refresh)

    def test_cli_upgrade_preview_denial_and_apply_keep_established_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            profile, _, _ = provision_rule_snapshot(home)
            baseline = tree_bytes(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, preview = invoke(
                    home,
                    ["rules", "upgrade", "preview", "--profile", profile["profileId"]],
                )
            self.assertEqual(code, 4)
            self.assertEqual(preview["status"], "permission_required")
            self.assertEqual(tree_bytes(home), baseline)

            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "permission": {**preview["permissionBinding"], "granted": False},
            }
            bundle_path = root / "evaluator-permission.json"
            write_canonical(bundle_path, bundle)
            code, denied = invoke(
                home,
                ["rules", "upgrade", "apply", "--input", str(bundle_path)],
            )
            self.assertEqual(code, 2)
            self.assertEqual(denied["status"], "invalid")
            self.assertEqual(tree_bytes(home), baseline)

            bundle["permission"]["granted"] = True
            write_canonical(bundle_path, bundle)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, applied = invoke(
                    home,
                    ["rules", "upgrade", "apply", "--input", str(bundle_path)],
                )
            self.assertEqual(code, 0)
            self.assertTrue(applied["changed"])
            self.assertEqual(
                applied["authorization"]["evaluatorId"],
                "guardian-flutter-usage-rules-v2",
            )

    def test_apply_rechecks_races_and_recovers_only_the_exact_interrupted_record(self) -> None:
        import guardian_core.evaluator_upgrade as upgrade
        import guardian_core.rule_activation as activation

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _, _ = provision_rule_snapshot(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = upgrade.preview_evaluator_upgrade(home, profile_id=profile["profileId"])
            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "permission": {**preview["permissionBinding"], "granted": True},
            }
            later_catalog = signed_catalog_v2(profile, sequence=3)
            original_lock = upgrade.profile_transaction_lock

            @contextmanager
            def racing_lock(lock_home: Path, profile_id: str):
                with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                    activation.ingest_rule_snapshot(home, profile, later_catalog)
                with original_lock(lock_home, profile_id):
                    yield

            before_race = tree_bytes(home)
            with (
                patch("guardian_core.evaluator_upgrade.profile_transaction_lock", racing_lock),
                patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW),
                self.assertRaises(upgrade.EvaluatorUpgradeError),
            ):
                upgrade.apply_evaluator_upgrade(home, bundle)
            self.assertNotEqual(tree_bytes(home), before_race)
            paths = upgrade.GuardianPaths(home)
            self.assertFalse(paths.evaluator_authorizations(profile["profileId"]).exists())
            self.assertFalse(paths.current_evaluator_authorization(profile["profileId"]).exists())

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _, _ = provision_rule_snapshot(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = upgrade.preview_evaluator_upgrade(home, profile_id=profile["profileId"])
            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "permission": {**preview["permissionBinding"], "granted": True},
            }
            with (
                patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW),
                patch(
                    "guardian_core.evaluator_upgrade.contained_atomic_write_json",
                    side_effect=OSError("simulated pointer interruption"),
                ),
                self.assertRaises(upgrade.EvaluatorUpgradeError),
            ):
                upgrade.apply_evaluator_upgrade(home, bundle)
            history = upgrade.GuardianPaths(home).evaluator_authorizations(profile["profileId"])
            self.assertEqual(len(list(history.glob("*.json"))), 1)
            self.assertFalse(
                upgrade.GuardianPaths(home)
                .current_evaluator_authorization(profile["profileId"])
                .exists()
            )
            divergent = copy.deepcopy(bundle)
            divergent["permission"]["rulesDigest"] = "0" * 64
            interrupted = tree_bytes(home)
            with self.assertRaises(upgrade.EvaluatorUpgradeError):
                upgrade.apply_evaluator_upgrade(home, divergent)
            self.assertEqual(tree_bytes(home), interrupted)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                recovered = upgrade.apply_evaluator_upgrade(home, bundle)
            self.assertTrue(recovered["changed"])
            self.assertIsNotNone(upgrade.load_evaluator_authorization(home, profile["profileId"]))

    def test_authorization_is_profile_isolated_and_partial_or_tampered_state_fails(self) -> None:
        from guardian_core.evaluator_upgrade import (
            EvaluatorUpgradeError,
            GuardianPaths,
            apply_evaluator_upgrade,
            load_evaluator_authorization,
            preview_evaluator_upgrade,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            first, _, _ = provision_rule_snapshot(home, profile_id="first-company")
            second, _, _ = provision_rule_snapshot(home, profile_id="second-company")
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = preview_evaluator_upgrade(home, profile_id=first["profileId"])
                apply_evaluator_upgrade(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": first["profileId"],
                        "permission": {**preview["permissionBinding"], "granted": True},
                    },
                )
            self.assertIsNone(load_evaluator_authorization(home, second["profileId"]))

            paths = GuardianPaths(home)
            shutil.copytree(
                paths.evaluator_authorizations(first["profileId"]),
                paths.evaluator_authorizations(second["profileId"]),
            )
            shutil.copy2(
                paths.current_evaluator_authorization(first["profileId"]),
                paths.current_evaluator_authorization(second["profileId"]),
            )
            with self.assertRaises(EvaluatorUpgradeError):
                load_evaluator_authorization(home, second["profileId"])

            paths.current_evaluator_authorization(first["profileId"]).unlink()
            with self.assertRaises(EvaluatorUpgradeError):
                load_evaluator_authorization(home, first["profileId"])
            partial = tree_bytes(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, invalid = invoke(
                    home,
                    ["rules", "list", "--profile", first["profileId"]],
                )
            self.assertEqual(code, 2)
            self.assertEqual(invalid["status"], "invalid")
            self.assertNotIn(str(home), json.dumps(invalid, sort_keys=True))
            self.assertEqual(tree_bytes(home), partial)


class RulesListTest(unittest.TestCase):
    def test_pre_activation_inventory_is_honest_zero_write_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            snapshot = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW, sequence=1)
            baseline = tree_bytes(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, inventory = invoke(
                    home,
                    ["rules", "list", "--profile", profile["profileId"]],
                )
            self.assertEqual(code, 0)
            self.assertEqual(inventory["evaluatorState"], "pre_activation")
            self.assertIsNone(inventory["evaluatorId"])
            self.assertEqual(inventory["ruleSnapshotId"], snapshot["snapshotId"])
            self.assertEqual(inventory["rules"], [])
            self.assertEqual(
                inventory["summary"],
                {"active": 0, "informative": 0, "notAssessed": 0},
            )
            schema_validator("rules-list.schema.json").validate(inventory)
            self.assertEqual(tree_bytes(home), baseline)
    def test_list_is_canonical_private_and_zero_write_before_and_after_upgrade(self) -> None:
        from guardian_core.evaluator_upgrade import (
            apply_evaluator_upgrade,
            preview_evaluator_upgrade,
        )

        rules = [
            machine_rule(
                "button-primary.forbidden-widget",
                predicate_type="forbidden_identity_in_scope",
                scope="widget_class",
            ),
            informative_rule(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _, _ = provision_rule_snapshot(home, rules=rules)
            before = tree_bytes(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, legacy = invoke(
                    home,
                    ["rules", "list", "--profile", profile["profileId"]],
                )
            self.assertEqual(code, 0)
            self.assertEqual(legacy["evaluatorState"], "legacy_v1")
            self.assertEqual(legacy["summary"], {"active": 0, "informative": 1, "notAssessed": 1})
            self.assertEqual(tree_bytes(home), before)

            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = preview_evaluator_upgrade(home, profile_id=profile["profileId"])
                apply_evaluator_upgrade(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": profile["profileId"],
                        "permission": {**preview["permissionBinding"], "granted": True},
                    },
                )
                after_apply = tree_bytes(home)
                code, current = invoke(
                    home,
                    ["rules", "list", "--profile", profile["profileId"]],
                )
            self.assertEqual(code, 0)
            self.assertEqual(current["status"], "allowed")
            self.assertEqual(current["evaluatorState"], "authorized_v2")
            self.assertEqual(current["summary"], {"active": 1, "informative": 1, "notAssessed": 0})
            schema_validator("rules-list.schema.json").validate(current)
            self.assertEqual(
                [item["ruleId"] for item in current["rules"]],
                sorted(item["ruleId"] for item in rules),
            )
            rendered = json.dumps(current, sort_keys=True)
            for secret in (
                "Private design prose",
                "Private informational prose",
                "synthetic-rulebook",
                "private-figma-file",
                "99:1",
                "button.primary",
            ):
                self.assertNotIn(secret, rendered)
            self.assertEqual(tree_bytes(home), after_apply)

    def test_judgment_and_stale_source_use_established_exit_codes_without_writes(self) -> None:
        from guardian_core.evaluator_upgrade import (
            apply_evaluator_upgrade,
            preview_evaluator_upgrade,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _, _ = provision_rule_snapshot(home, rules=[judgment_rule()])
            baseline = tree_bytes(home)
            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                code, legacy = invoke(home, ["rules", "list", "--profile", profile["profileId"]])
            self.assertEqual(code, 0)
            self.assertEqual(legacy["rules"][0]["capabilityStatus"], "not_assessed")
            self.assertEqual(tree_bytes(home), baseline)

            with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
                preview = preview_evaluator_upgrade(home, profile_id=profile["profileId"])
                apply_evaluator_upgrade(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": profile["profileId"],
                        "permission": {
                            **preview["permissionBinding"],
                            "granted": True,
                        },
                    },
                )
                upgraded_baseline = tree_bytes(home)
                code, incomplete = invoke(
                    home,
                    ["rules", "list", "--profile", profile["profileId"]],
                )
            self.assertEqual(code, 4)
            self.assertEqual(incomplete["status"], "not_assessed")
            self.assertEqual(tree_bytes(home), upgraded_baseline)

            with patch(
                "guardian_core.evaluator_upgrade._utc_now",
                return_value=NOW + timedelta(days=8),
            ):
                code, stale = invoke(home, ["rules", "list", "--profile", profile["profileId"]])
            self.assertEqual(code, 3)
            self.assertEqual(stale["status"], "stale")
            self.assertEqual(tree_bytes(home), upgraded_baseline)


if __name__ == "__main__":
    unittest.main()

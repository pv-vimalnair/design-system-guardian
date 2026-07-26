from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from tests.catalog_authority_test_support import attest_catalog
from tests.guardian_test_support import ingest_test_snapshot
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PLUGIN_ROOT / "schemas"
ACTIVE_CAPABILITIES = [
    {
        "predicate": "forbidden_identity_in_scope",
        "scope": "compilation_unit",
    },
    {
        "predicate": "max_instances_per_scope",
        "scope": "compilation_unit",
    },
]


def machine_rule(
    rule_id: str = "button-primary.maximum",
    *,
    predicate_type: str = "max_instances_per_scope",
    scope: str = "compilation_unit",
) -> dict:
    predicate: dict[str, object]
    if predicate_type == "max_instances_per_scope":
        predicate = {
            "type": predicate_type,
            "identity": "button.primary",
            "scope": scope,
            "max": 1,
        }
    else:
        predicate = {
            "type": predicate_type,
            "identity": "button.primary",
            "scope": scope,
        }
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "machine",
        "predicate": predicate,
        "appliesTo": {"kind": "component", "identity": "button.primary"},
        "provenance": {
            "origin": "figma_description",
            "figma": {
                "fileKey": "figma-brand",
                "nodeId": "1:2",
                "sourceVersion": "42",
            },
            "docRef": None,
        },
    }


def catalog_v2(*, rules: list[dict] | None = None, complete: bool = True) -> dict:
    catalog = sample_catalog()
    catalog["schemaVersion"] = 2
    catalog["rules"] = copy.deepcopy(rules if rules is not None else [machine_rule()])
    catalog["ruleEvidence"] = {
        "captureAttempted": True,
        "sourceComplete": complete,
    }
    return catalog


def signed_catalog_v2(
    profile: dict,
    *,
    sequence: int = 2,
    rules: list[dict] | None = None,
    complete: bool = True,
) -> dict:
    return attest_catalog(
        catalog_v2(rules=rules, complete=complete),
        profile,
        sequence=sequence,
        issued_at=NOW,
    )


def tree_bytes(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def v1_state_bytes(home: Path, profile_id: str) -> dict[str, bytes]:
    profile_root = home / "profiles" / profile_id
    paths = [
        profile_root / "profile.json",
        profile_root / "current-snapshot.json",
        *(profile_root / "snapshots").glob("*.json"),
        *(profile_root / "approval-sequences").glob("*.json"),
    ]
    return {
        path.relative_to(home).as_posix(): path.read_bytes()
        for path in sorted(paths, key=lambda item: item.as_posix())
    }


class RuleActivationSchemaTest(unittest.TestCase):
    def validator(self, name: str) -> Draft202012Validator:
        store = {
            payload["$id"]: payload
            for path in SCHEMA_ROOT.glob("*.schema.json")
            for payload in [json.loads(path.read_text(encoding="utf-8"))]
        }
        schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        registry = Registry().with_resources(
            (schema_id, Resource.from_contents(payload))
            for schema_id, payload in store.items()
        )
        return Draft202012Validator(
            schema,
            registry=registry,
        )

    def test_new_contracts_are_strict_and_pin_v2(self) -> None:
        snapshot_schema = json.loads(
            (SCHEMA_ROOT / "rule-activation-snapshot.schema.json").read_text(
                encoding="utf-8"
            )
        )
        permission_schema = json.loads(
            (SCHEMA_ROOT / "rule-activation-permission.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(snapshot_schema["additionalProperties"])
        self.assertEqual(snapshot_schema["properties"]["schemaVersion"], {"const": 2})
        self.assertFalse(permission_schema["additionalProperties"])
        self.assertEqual(
            snapshot_schema["properties"]["activatedCapabilities"]["const"],
            ACTIVE_CAPABILITIES,
        )
        self.validator("rule-activation-snapshot.schema.json")
        self.validator("rule-activation-permission.schema.json")


class RuleActivationFlowTest(unittest.TestCase):
    def provision(self, home: Path) -> tuple[dict, dict]:
        profile = sample_profile()
        v1 = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW, sequence=1)
        return profile, v1

    def test_preview_is_zero_write_and_apply_is_append_only_and_idempotent(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.preflight import load_run_pin, preflight_snapshot
        from guardian_core.rule_activation import (
            apply_rule_activation,
            preview_rule_activation,
        )
        from guardian_core.snapshot import load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            project = home.parent / f"{home.name}-project"
            project.mkdir()
            profile, v1 = self.provision(home)
            before = tree_bytes(home)
            v1_before = v1_state_bytes(home, profile["profileId"])
            catalog = signed_catalog_v2(profile)

            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                preview = preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=catalog,
                )
            self.assertEqual(preview["status"], "permission_required")
            self.assertTrue(preview["permissionRequired"])
            self.assertFalse(preview["localChangesPerformed"])
            self.assertEqual(tree_bytes(home), before)

            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "catalog": catalog,
                "permission": {
                    **preview["permissionBinding"],
                    "granted": True,
                },
            }
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                first = apply_rule_activation(home, bundle)
            RuleActivationSchemaTest().validator(
                "rule-activation-permission.schema.json"
            ).validate(bundle)
            RuleActivationSchemaTest().validator(
                "rule-activation-snapshot.schema.json"
            ).validate(first["snapshot"])
            after_first = tree_bytes(home)
            self.assertEqual(
                v1_state_bytes(home, profile["profileId"]),
                v1_before,
                "Activation must preserve every v1 profile, snapshot, sequence, and pointer byte.",
            )
            self.assertTrue(first["changed"])
            self.assertEqual(first["snapshot"]["schemaVersion"], 2)
            self.assertEqual(first["snapshot"]["previousSnapshotId"], v1["snapshotId"])
            self.assertEqual(first["snapshot"]["rulesDigest"], sha256_digest([machine_rule()]))
            self.assertEqual(first["snapshot"]["activatedCapabilities"], ACTIVE_CAPABILITIES)
            self.assertEqual(
                load_snapshot(home, profile["profileId"])["snapshotId"],
                first["snapshot"]["snapshotId"],
            )
            self.assertEqual(
                load_snapshot(home, profile["profileId"], v1["snapshotId"]),
                v1,
            )

            with patch(
                "guardian_core.rule_activation._utc_now",
                return_value=NOW + timedelta(days=1),
            ):
                repeated = apply_rule_activation(home, bundle)
            self.assertFalse(repeated["changed"])
            self.assertEqual(repeated["snapshot"], first["snapshot"])
            self.assertEqual(tree_bytes(home), after_first)

            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                pin_result = preflight_snapshot(
                    home,
                    profile_id=profile["profileId"],
                    run_id="rule-run",
                    policy_digest=v1["policyDigest"],
                    project_root=project,
                )
            self.assertEqual(pin_result["pin"]["snapshotId"], first["snapshot"]["snapshotId"])
            self.assertEqual(
                set(pin_result["pin"]),
                {
                    "schemaVersion",
                    "runId",
                    "profileId",
                    "profileDigest",
                    "snapshotId",
                    "catalogDigest",
                    "policyDigest",
                    "sourceCut",
                    "sourceState",
                    "degraded",
                    "approvalSequence",
                    "approvalDigest",
                    "projectBinding",
                    "authoritySeal",
                },
            )
            loaded = load_run_pin(
                home,
                profile_id=profile["profileId"],
                run_id="rule-run",
            )
            self.assertEqual(loaded["snapshot"]["schemaVersion"], 2)
            self.assertEqual(loaded["snapshot"]["rulesDigest"], first["snapshot"]["rulesDigest"])

    def test_denial_mismatch_and_sequence_gap_are_zero_write(self) -> None:
        from guardian_core.rule_activation import (
            RuleActivationError,
            apply_rule_activation,
            preview_rule_activation,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            catalog = signed_catalog_v2(profile)
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                preview = preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=catalog,
                )
            baseline = tree_bytes(home)
            permission = {**preview["permissionBinding"], "granted": False}
            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "catalog": catalog,
                "permission": permission,
            }
            with self.assertRaises(RuleActivationError):
                apply_rule_activation(home, bundle)
            self.assertEqual(tree_bytes(home), baseline)

            bundle["permission"] = {
                **preview["permissionBinding"],
                "granted": True,
                "candidateRulesDigest": "0" * 64,
            }
            with self.assertRaises(RuleActivationError):
                apply_rule_activation(home, bundle)
            self.assertEqual(tree_bytes(home), baseline)

            gap = signed_catalog_v2(profile, sequence=3)
            with self.assertRaises(RuleActivationError):
                preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=gap,
                )
            self.assertEqual(tree_bytes(home), baseline)

    def test_v2_evidence_corruption_never_falls_back_and_v1_cannot_advance(self) -> None:
        from guardian_core.rule_activation import (
            RuleActivationError,
            apply_rule_activation,
            preview_rule_activation,
        )
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            catalog = signed_catalog_v2(profile)
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                preview = preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=catalog,
                )
                apply_rule_activation(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": profile["profileId"],
                        "catalog": catalog,
                        "permission": {
                            **preview["permissionBinding"],
                            "granted": True,
                        },
                    },
                )

            with self.assertRaises(SnapshotValidationError):
                ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW),
                )

            pointer = home / "profiles" / profile["profileId"] / "current-rule-snapshot.json"
            pointer.unlink()
            with self.assertRaises((RuleActivationError, SnapshotValidationError)):
                load_snapshot(home, profile["profileId"])

    def test_incomplete_capture_blocks_but_deferred_rules_are_stored(self) -> None:
        from guardian_core.preflight import preflight_snapshot
        from guardian_core.rule_activation import (
            RuleActivationError,
            apply_rule_activation,
            preview_rule_activation,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            incomplete = signed_catalog_v2(profile, complete=False)
            before = tree_bytes(home)
            with self.assertRaises(RuleActivationError):
                preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=incomplete,
                )
            self.assertEqual(tree_bytes(home), before)

            deferred = signed_catalog_v2(
                profile,
                rules=[machine_rule(scope="widget_class")],
            )
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                preview = preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=deferred,
                )
                applied = apply_rule_activation(
                    home,
                    {
                        "schemaVersion": 1,
                        "profileId": profile["profileId"],
                        "catalog": deferred,
                        "permission": {
                            **preview["permissionBinding"],
                            "granted": True,
                        },
                    },
                )
            self.assertEqual(applied["snapshot"]["rules"], [machine_rule(scope="widget_class")])
            self.assertEqual(applied["snapshot"]["ruleValidation"]["status"], "not_assessed")
            self.assertIn(
                "unsupported_predicate_scope",
                applied["snapshot"]["ruleValidation"]["reasonCodes"],
            )
            project = home / "deferred-project"
            project.mkdir()
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                result = preflight_snapshot(
                    home,
                    profile_id=profile["profileId"],
                    run_id="deferred-rule-run",
                    policy_digest=applied["snapshot"]["policyDigest"],
                    project_root=project,
                )
            self.assertEqual(result["status"], "not_assessed")
            self.assertIsNone(result["pin"])
            self.assertFalse(result["pinCreated"])

    def test_preview_never_repairs_a_missing_v1_pointer(self) -> None:
        from guardian_core.rule_activation import RuleActivationError, preview_rule_activation

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            pointer = (
                home
                / "profiles"
                / profile["profileId"]
                / "current-snapshot.json"
            )
            pointer.unlink()
            before = tree_bytes(home)
            with (
                patch("guardian_core.rule_activation._utc_now", return_value=NOW),
                self.assertRaises(RuleActivationError),
            ):
                preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=signed_catalog_v2(profile),
                )
            self.assertEqual(tree_bytes(home), before)
            self.assertFalse(pointer.exists())

    def test_interrupted_first_activation_recovers_exact_evidence_across_time(self) -> None:
        import guardian_core.rule_activation as activation

        for interruption in ("after_snapshot", "after_sequence"):
            with self.subTest(interruption=interruption), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                profile, _ = self.provision(home)
                catalog = signed_catalog_v2(profile)
                with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                    preview = activation.preview_rule_activation(
                        home,
                        profile_id=profile["profileId"],
                        catalog_document=catalog,
                    )
                bundle = {
                    "schemaVersion": 1,
                    "profileId": profile["profileId"],
                    "catalog": catalog,
                    "permission": {
                        **preview["permissionBinding"],
                        "granted": True,
                    },
                }
                if interruption == "after_snapshot":
                    original = activation.exclusive_write_json
                    calls = 0

                    def interrupt_sequence(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            raise OSError("simulated sequence interruption")
                        return original(*args, **kwargs)

                    fault = patch(
                        "guardian_core.rule_activation.exclusive_write_json",
                        side_effect=interrupt_sequence,
                    )
                else:
                    fault = patch(
                        "guardian_core.rule_activation.contained_atomic_write_json",
                        side_effect=OSError("simulated pointer interruption"),
                    )
                with (
                    patch("guardian_core.rule_activation._utc_now", return_value=NOW),
                    fault,
                    self.assertRaises(activation.RuleActivationError),
                ):
                    activation.apply_rule_activation(home, bundle)

                profile_root = home / "profiles" / profile["profileId"]
                retained = sorted((profile_root / "rule-snapshots").glob("*.json"))
                self.assertEqual(len(retained), 1)
                retained_id = retained[0].stem
                interrupted_state = tree_bytes(home)
                divergent = copy.deepcopy(bundle)
                divergent["permission"]["candidateRulesDigest"] = "0" * 64
                with (
                    patch(
                        "guardian_core.rule_activation._utc_now",
                        return_value=NOW + timedelta(seconds=1),
                    ),
                    self.assertRaises(activation.RuleActivationError),
                ):
                    activation.apply_rule_activation(home, divergent)
                self.assertEqual(tree_bytes(home), interrupted_state)

                with patch(
                    "guardian_core.rule_activation._utc_now",
                    return_value=NOW + timedelta(days=1),
                ):
                    recovered = activation.apply_rule_activation(home, bundle)
                self.assertTrue(recovered["changed"])
                self.assertEqual(recovered["snapshot"]["snapshotId"], retained_id)
                self.assertTrue(
                    (profile_root / "current-rule-snapshot.json").is_file()
                )
                self.assertEqual(
                    len(list((profile_root / "rule-approval-sequences").glob("*.json"))),
                    1,
                )

    def test_interrupted_later_refresh_recovers_only_the_exact_signed_retry(self) -> None:
        import guardian_core.rule_activation as activation

        for interruption in ("after_snapshot", "after_sequence"):
            with self.subTest(interruption=interruption), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                profile, _ = self.provision(home)
                first_catalog = signed_catalog_v2(profile, sequence=2)
                with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                    preview = activation.preview_rule_activation(
                        home,
                        profile_id=profile["profileId"],
                        catalog_document=first_catalog,
                    )
                    activation.apply_rule_activation(
                        home,
                        {
                            "schemaVersion": 1,
                            "profileId": profile["profileId"],
                            "catalog": first_catalog,
                            "permission": {
                                **preview["permissionBinding"],
                                "granted": True,
                            },
                        },
                    )
                profile_root = home / "profiles" / profile["profileId"]
                before_ids = {
                    path.stem
                    for path in (profile_root / "rule-snapshots").glob("*.json")
                }
                next_catalog = signed_catalog_v2(profile, sequence=3)
                if interruption == "after_snapshot":
                    original = activation.exclusive_write_json
                    calls = 0

                    def interrupt_sequence(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            raise OSError("simulated refresh sequence interruption")
                        return original(*args, **kwargs)

                    fault = patch(
                        "guardian_core.rule_activation.exclusive_write_json",
                        side_effect=interrupt_sequence,
                    )
                else:
                    fault = patch(
                        "guardian_core.rule_activation.contained_atomic_write_json",
                        side_effect=OSError("simulated refresh pointer interruption"),
                    )
                with (
                    patch("guardian_core.rule_activation._utc_now", return_value=NOW),
                    fault,
                    self.assertRaises(activation.RuleActivationError),
                ):
                    activation.ingest_rule_snapshot(home, profile, next_catalog)
                after_ids = {
                    path.stem
                    for path in (profile_root / "rule-snapshots").glob("*.json")
                }
                retained_ids = after_ids - before_ids
                self.assertEqual(len(retained_ids), 1)
                retained_id = retained_ids.pop()

                divergent_catalog = signed_catalog_v2(
                    profile,
                    sequence=3,
                    rules=[machine_rule("button-primary.different-maximum")],
                )
                interrupted_state = tree_bytes(home)
                with (
                    patch(
                        "guardian_core.rule_activation._utc_now",
                        return_value=NOW + timedelta(seconds=1),
                    ),
                    self.assertRaises(activation.RuleActivationError),
                ):
                    activation.ingest_rule_snapshot(
                        home,
                        profile,
                        divergent_catalog,
                    )
                self.assertEqual(tree_bytes(home), interrupted_state)

                with patch(
                    "guardian_core.rule_activation._utc_now",
                    return_value=NOW + timedelta(days=1),
                ):
                    recovered = activation.ingest_rule_snapshot(
                        home,
                        profile,
                        next_catalog,
                    )
                self.assertEqual(recovered["snapshotId"], retained_id)
                self.assertEqual(
                    len(list((profile_root / "rule-approval-sequences").glob("*.json"))),
                    2,
                )
                after_recovery = tree_bytes(home)
                with patch(
                    "guardian_core.rule_activation._utc_now",
                    return_value=NOW + timedelta(days=2),
                ):
                    replay = activation.ingest_rule_snapshot(
                        home,
                        profile,
                        next_catalog,
                    )
                self.assertEqual(replay, recovered)
                self.assertEqual(tree_bytes(home), after_recovery)

    def test_concurrent_v1_advance_blocks_before_any_v2_write(self) -> None:
        import guardian_core.rule_activation as activation
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            catalog = signed_catalog_v2(profile)
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                preview = activation.preview_rule_activation(
                    home,
                    profile_id=profile["profileId"],
                    catalog_document=catalog,
                )
            bundle = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "catalog": catalog,
                "permission": {
                    **preview["permissionBinding"],
                    "granted": True,
                },
            }
            next_v1 = attest_catalog(
                sample_catalog(),
                profile,
                sequence=2,
                issued_at=NOW,
            )
            original_lock = activation.profile_transaction_lock

            @contextmanager
            def racing_lock(lock_home: Path, profile_id: str):
                with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                    ingest_snapshot(home, profile, next_v1)
                with original_lock(lock_home, profile_id):
                    yield

            with (
                patch("guardian_core.rule_activation._utc_now", return_value=NOW),
                patch(
                    "guardian_core.rule_activation.profile_transaction_lock",
                    racing_lock,
                ),
                self.assertRaises(activation.RuleActivationError),
            ):
                activation.apply_rule_activation(home, bundle)
            profile_root = home / "profiles" / profile["profileId"]
            self.assertFalse((profile_root / "rule-snapshots").exists())
            self.assertFalse((profile_root / "rule-approval-sequences").exists())
            self.assertFalse((profile_root / "current-rule-snapshot.json").exists())
            self.assertEqual(
                sorted(path.stem for path in (profile_root / "approval-sequences").glob("*.json")),
                ["1", "2"],
            )

    def test_cli_activation_preserves_preview_apply_and_error_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            profile, _ = self.provision(home)
            catalog = signed_catalog_v2(profile)
            catalog_path = root / "catalog-v2.json"
            write_canonical(catalog_path, catalog)
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                code, preview = invoke(
                    home,
                    [
                        "rules",
                        "activate",
                        "preview",
                        "--profile",
                        profile["profileId"],
                        "--input",
                        str(catalog_path),
                    ],
                )
            self.assertEqual(code, 4)
            self.assertEqual(preview["status"], "permission_required")
            baseline = tree_bytes(home)

            denied = {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "catalog": catalog,
                "permission": {
                    **preview["permissionBinding"],
                    "granted": False,
                },
            }
            denied_path = root / "denied.json"
            write_canonical(denied_path, denied)
            code, result = invoke(
                home,
                ["rules", "activate", "apply", "--input", str(denied_path)],
            )
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(tree_bytes(home), baseline)

            permitted = copy.deepcopy(denied)
            permitted["permission"]["granted"] = True
            permitted_path = root / "permitted.json"
            write_canonical(permitted_path, permitted)
            with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
                code, applied = invoke(
                    home,
                    ["rules", "activate", "apply", "--input", str(permitted_path)],
                )
            self.assertEqual(code, 0)
            self.assertTrue(applied["changed"])
            with patch(
                "guardian_core.rule_activation._utc_now",
                return_value=NOW + timedelta(days=1),
            ):
                code, replay = invoke(
                    home,
                    ["rules", "activate", "apply", "--input", str(permitted_path)],
                )
            self.assertEqual(code, 0)
            self.assertFalse(replay["changed"])


if __name__ == "__main__":
    unittest.main()

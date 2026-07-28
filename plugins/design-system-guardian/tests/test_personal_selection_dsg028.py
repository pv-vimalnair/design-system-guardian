from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_onboarding_dsg017 import file_state
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


TARGET_FILE = "figma-working-file"
TARGET_VERSION = "work-17"
UNSELECTED_FILE = "figma-community-kit"


def personal_discovery(
    project_root: Path,
    *,
    target_file: str = TARGET_FILE,
    target_version: str = TARGET_VERSION,
) -> dict:
    """Return synthetic, complete local Figma discovery with an exact partition."""

    result = {
        "schemaVersion": 1,
        "projectRoot": str(project_root.resolve()),
        "targetFigmaFile": {
            "fileKey": target_file,
            "version": target_version,
            "name": "Checkout working file",
        },
        "discoveryComplete": True,
        "candidates": [
            {
                "fileKey": "figma-brand",
                "version": "42",
                "name": "Brand library",
                "published": True,
                "decision": "use",
            },
            {
                "fileKey": "figma-product",
                "version": "91",
                "name": "Product library",
                "published": True,
                "decision": "use",
            },
            {
                "fileKey": UNSELECTED_FILE,
                "version": "8",
                "name": "Unrelated community kit",
                "published": True,
                "decision": "do_not_use",
            },
        ],
        "adapters": copy.deepcopy(sample_profile()["adapters"]),
        "catalog": copy.deepcopy(sample_catalog()),
    }
    result["catalog"]["tokenProvenance"].update(
        {"source": "figma-brand", "sourceVersion": "42"}
    )
    color_binding = {
        "bindingType": "variable",
        "fileKey": "figma-brand",
        "sourceVersion": "42",
        "key": "variable-key-primary",
        "collectionKey": "collection-key-color",
        "resolvedType": "COLOR",
    }
    space_binding = {
        "bindingType": "variable",
        "fileKey": "figma-brand",
        "sourceVersion": "42",
        "key": "variable-key-space-200",
        "collectionKey": "collection-key-space",
        "resolvedType": "FLOAT",
    }
    result["catalog"]["tokens"]["color"]["action"]["primary"]["$extensions"] = {
        "guardian.figma": copy.deepcopy(color_binding)
    }
    result["catalog"]["tokens"]["space"]["200"]["$extensions"] = {
        "guardian.figma": copy.deepcopy(space_binding)
    }

    from guardian_core.canonical import sha256_digest
    from guardian_core.dtcg_resolver import materialize_resolver_tokens

    resolved_tokens = materialize_resolver_tokens(
        result["catalog"]["tokens"],
        result["catalog"]["resolver"],
        result["catalog"]["resolverContext"],
    )["tokens"]

    from guardian_core.personal_selection import personal_catalog_readback_digest

    result["catalogReadback"] = {
        "schemaVersion": 1,
        "method": "figma_plugin_api_catalog_readback",
        "complete": True,
        "evidenceAuthority": "unprotected_caller_carried",
        "contractDigest": personal_catalog_readback_digest(),
        "sources": [
            {"fileKey": "figma-brand", "version": "42", "published": True},
            {"fileKey": "figma-product", "version": "91", "published": True},
        ],
        "tokens": [
            {
                "identity": "color.action.primary",
                "published": True,
                "binding": copy.deepcopy(color_binding),
                "tokenDigest": sha256_digest(resolved_tokens["color.action.primary"]),
            },
            {
                "identity": "space.200",
                "published": True,
                "binding": copy.deepcopy(space_binding),
                "tokenDigest": sha256_digest(resolved_tokens["space.200"]),
            },
        ],
        "assets": [
            {
                "kind": kind,
                "identity": asset["identity"],
                "sourceVersion": asset["sourceVersion"],
                "figma": copy.deepcopy(asset["figma"]),
                "designContractDigest": sha256_digest(
                    {
                        "variants": asset["variants"],
                        "properties": asset["properties"],
                    }
                ),
                "codeMappingsDigest": sha256_digest(asset["codeMappings"]),
            }
            for plural, kind in (("components", "component"), ("icons", "icon"))
            for asset in result["catalog"]["registry"][plural]
        ],
    }
    return result


def permitted_selection(preview: dict, discovery: dict) -> dict:
    request = copy.deepcopy(discovery)
    request["permission"] = {
        **copy.deepcopy(preview["permissionBinding"]),
        "granted": True,
    }
    return request


def apply_selection(home: Path, project: Path, *, run_id: str = "run-personal-1") -> dict:
    from guardian_core.personal_selection import (
        apply_personal_selection,
        prepare_selection_preview,
    )

    discovery = personal_discovery(project)
    preview = prepare_selection_preview(home, run_id=run_id, discovery=discovery)
    with patch("guardian_core.snapshot._utc_now", return_value=NOW):
        return apply_personal_selection(home, permitted_selection(preview, discovery))


class PersonalSelectionContractTest(unittest.TestCase):
    def test_preview_is_zero_write_and_partitions_every_candidate_exactly(self) -> None:
        from guardian_core.personal_selection import prepare_selection_preview

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            discovery = personal_discovery(project)

            preview = prepare_selection_preview(
                home,
                run_id="run-preview",
                discovery=discovery,
            )

            self.assertEqual(preview["status"], "permission_required")
            self.assertEqual(preview["authorityMode"], "personal_local")
            self.assertEqual(preview["runId"], "run-preview")
            self.assertEqual(preview["targetFigmaFile"], discovery["targetFigmaFile"])
            self.assertEqual(
                [
                    (item["name"], item["decision"])
                    for item in preview["libraryChoices"]
                ],
                [
                    ("Brand library", "use"),
                    ("Unrelated community kit", "do_not_use"),
                    ("Product library", "use"),
                ],
            )
            self.assertEqual(
                preview["selectedLibraryFileKeys"],
                ["figma-brand", "figma-product"],
            )
            self.assertEqual(preview["excludedLibraryFileKeys"], [UNSELECTED_FILE])
            self.assertEqual(
                set(preview["selectedLibraryFileKeys"])
                | set(preview["excludedLibraryFileKeys"]),
                {candidate["fileKey"] for candidate in discovery["candidates"]},
            )
            self.assertFalse(
                set(preview["selectedLibraryFileKeys"])
                & set(preview["excludedLibraryFileKeys"])
            )
            self.assertFalse(home.exists())

    def test_empty_use_or_incomplete_discovery_is_rejected_without_writes(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()

            empty_use = personal_discovery(project)
            for candidate in empty_use["candidates"]:
                candidate["decision"] = "do_not_use"
            incomplete = personal_discovery(project)
            incomplete["discoveryComplete"] = False

            for name, discovery in (("empty-use", empty_use), ("incomplete", incomplete)):
                home = root / f"home-{name}"
                with self.subTest(name=name), self.assertRaises(PersonalSelectionError):
                    prepare_selection_preview(home, run_id=f"run-{name}", discovery=discovery)
                self.assertFalse(home.exists())

    def test_apply_rejects_every_permission_binding_drift_without_writes(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            apply_personal_selection,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            discovery = personal_discovery(project)
            preview = prepare_selection_preview(
                root / "preview-home",
                run_id="run-bound",
                discovery=discovery,
            )

            changed_decision = personal_discovery(project)
            changed_decision["candidates"][1]["decision"] = "do_not_use"
            changed_version = personal_discovery(project)
            changed_version["candidates"][0]["version"] = "43"
            changed_target = personal_discovery(
                project,
                target_file="another-working-file",
            )
            changed_catalog = personal_discovery(project)
            changed_catalog["catalog"]["tokens"]["space"]["200"]["$value"]["value"] = 12
            changed_run = personal_discovery(project)

            cases = [
                ("decision", changed_decision, None),
                ("candidate-version", changed_version, None),
                ("target", changed_target, None),
                ("catalog", changed_catalog, None),
                ("run", changed_run, "another-run"),
            ]
            for name, changed, permission_run in cases:
                home = root / f"home-{name}"
                request = permitted_selection(preview, changed)
                if permission_run is not None:
                    request["permission"]["runId"] = permission_run
                with self.subTest(name=name), self.assertRaises(PersonalSelectionError):
                    apply_personal_selection(home, request)
                self.assertFalse(home.exists())

    def test_apply_creates_local_personal_context_and_excludes_unselected_sources(self) -> None:
        from guardian_core.personal_selection import inspect_personal_selection
        from guardian_core.profile import load_profile
        from guardian_core.snapshot import load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()

            applied = apply_selection(home, project)

            self.assertEqual(applied["status"], "allowed")
            self.assertEqual(applied["authorityMode"], "personal_local")
            self.assertTrue(applied["localChangesPerformed"])
            self.assertTrue((home / "trust" / "policy-v1.json").is_file())
            self.assertTrue((home / "trust" / "snapshot-authority-v1.key").is_file())
            profile = load_profile(home, applied["profileId"])
            self.assertEqual(
                [item["fileKey"] for item in profile["figma"]["allowlistedLibraryFiles"]],
                ["figma-brand", "figma-product"],
            )
            snapshot = load_snapshot(home, applied["profileId"], applied["snapshotId"])
            source_keys = {
                item["fileKey"] for item in snapshot["sourceCut"]["figmaFiles"]
            }
            registry_keys = {
                asset["figma"]["fileKey"]
                for kind in ("components", "icons")
                for asset in snapshot["registry"][kind]
            }
            self.assertNotIn(UNSELECTED_FILE, source_keys)
            self.assertNotIn(UNSELECTED_FILE, registry_keys)
            status = inspect_personal_selection(home, run_id="run-personal-1")
            self.assertEqual(status["status"], "allowed")
            self.assertEqual(status["selectionDigest"], applied["selectionDigest"])
            self.assertEqual(status["targetFigmaFile"]["fileKey"], TARGET_FILE)

    def test_each_new_run_and_target_file_requires_a_new_selection(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            apply_personal_selection,
            inspect_personal_selection,
            prepare_selection_preview,
        )
        from guardian_core.preflight import PreflightError, preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            first = apply_selection(home, project, run_id="run-one")
            before = file_state(home)

            status = inspect_personal_selection(home, run_id="run-two")
            self.assertEqual(status["status"], "selection_required")
            self.assertEqual(file_state(home), before)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                with self.assertRaises(PreflightError):
                    preflight_snapshot(
                        home,
                        profile_id=first["profileId"],
                        run_id="run-two",
                        policy_digest=first["policyDigest"],
                        project_root=project,
                    )

            changed_target = personal_discovery(
                project,
                target_file="figma-another-working-file",
                target_version="work-1",
            )
            preview = prepare_selection_preview(
                home,
                run_id="run-two",
                discovery=changed_target,
            )
            replay = permitted_selection(preview, changed_target)
            replay["permission"] = copy.deepcopy(
                prepare_selection_preview(
                    home,
                    run_id="run-one",
                    discovery=personal_discovery(project),
                )["permissionBinding"]
            )
            replay["permission"]["granted"] = True
            with self.assertRaises(PersonalSelectionError):
                apply_personal_selection(home, replay)

    def test_personal_preflight_is_v2_and_bound_to_the_exact_selection(self) -> None:
        from guardian_core.preflight import load_run_pin, preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            applied = apply_selection(home, project, run_id="run-v2")

            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                result = preflight_snapshot(
                    home,
                    profile_id=applied["profileId"],
                    run_id="run-v2",
                    policy_digest=applied["policyDigest"],
                    project_root=project,
                )

            pin = result["pin"]
            self.assertEqual(pin["schemaVersion"], 2)
            self.assertEqual(pin["authorityMode"], "personal_local")
            self.assertEqual(pin["selectionDigest"], applied["selectionDigest"])
            self.assertEqual(pin["targetFigmaFile"]["fileKey"], TARGET_FILE)
            self.assertEqual(
                pin["selectedLibraryFileKeys"],
                ["figma-brand", "figma-product"],
            )
            self.assertEqual(pin["excludedLibraryFileKeys"], [UNSELECTED_FILE])
            loaded = load_run_pin(
                home,
                profile_id=applied["profileId"],
                run_id="run-v2",
            )["pin"]
            self.assertEqual(loaded, pin)

    def test_personal_allowed_resolution_is_visibly_unprotected_local_guidance(self) -> None:
        from guardian_core.preflight import preflight_snapshot
        from guardian_core.resolver import _resolve_pinned_identity_at_home
        from tests.test_root_schemas_strict_dsg003 import validator

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            applied = apply_selection(home, project, run_id="run-local-resolution")
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id=applied["profileId"],
                    run_id="run-local-resolution",
                    policy_digest=applied["policyDigest"],
                    project_root=project,
                )

            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                resolution = _resolve_pinned_identity_at_home(
                    home,
                    profile_id=applied["profileId"],
                    run_id="run-local-resolution",
                    request={
                        "requestId": "personal-local-token",
                        "kind": "token",
                        "identity": "color.action.primary",
                    },
                )

            self.assertEqual(resolution["status"], "allowed")
            self.assertEqual(
                resolution["evidence"]["authorityMode"],
                "personal_local",
            )
            self.assertFalse(resolution["evidence"]["independentProvenance"])
            self.assertFalse(resolution["evidence"]["productionReady"])

            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                missing = _resolve_pinned_identity_at_home(
                    home,
                    profile_id=applied["profileId"],
                    run_id="run-local-resolution",
                    request={
                        "requestId": "personal-local-missing",
                        "kind": "icon",
                        "identity": "icon.not-in-selected-catalog",
                    },
                )

            self.assertEqual(missing["status"], "missing")
            self.assertEqual(
                missing["evidence"]["reason"],
                "absent_from_complete_selected_local_catalog",
            )
            self.assertEqual(
                missing["evidence"]["authorityMode"],
                "personal_local",
            )
            self.assertFalse(missing["evidence"]["independentProvenance"])
            self.assertFalse(missing["evidence"]["productionReady"])
            self.assertEqual(missing["sentinel"]["label"], "MISSING ICON")
            self.assertFalse(missing["sentinel"]["productionReady"])
            resolution_validator = validator("resolution.schema.json")
            resolution_validator.validate(resolution)
            resolution_validator.validate(missing)

    def test_existing_enterprise_preflight_remains_schema_v1(self) -> None:
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "enterprise-home"
            project = Path(directory) / "enterprise-project"
            project.mkdir()
            snapshot = ingest_test_snapshot(
                home,
                sample_profile(),
                sample_catalog(),
                now=NOW,
            )

            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                result = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-enterprise-v1",
                    policy_digest=snapshot["policyDigest"],
                    project_root=project,
                )

            self.assertEqual(result["pin"]["schemaVersion"], 1)
            self.assertNotIn("authorityMode", result["pin"])
            self.assertNotIn("selectionDigest", result["pin"])
            self.assertNotIn("targetFigmaFile", result["pin"])

    def test_enterprise_profile_named_personal_enterprise_keeps_ed25519_route(self) -> None:
        from guardian_core.policy import verify_personal_profile_authority_binding

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "enterprise-home"
            profile = sample_profile("personal-enterprise")
            catalog = sample_catalog("personal-enterprise")

            snapshot = ingest_test_snapshot(home, profile, catalog, now=NOW)

            self.assertEqual(snapshot["profileId"], "personal-enterprise")
            self.assertEqual(
                snapshot["catalogEvidence"]["approvalAttestation"]["algorithm"],
                "ed25519",
            )
            self.assertIsNone(
                verify_personal_profile_authority_binding(
                    home,
                    "personal-enterprise",
                    missing_ok=True,
                )
            )

    def test_status_rejects_orphaned_dependencies_without_writing_or_repairing(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            inspect_personal_selection,
        )
        from guardian_core.profile import profile_path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, kind in enumerate((
                "authority",
                "profile",
                "snapshot",
                "current-pointer",
            )):
                home = root / f"home-{kind}"
                project = root / f"project-{kind}"
                project.mkdir()
                run_id = f"run-orphan-{index}"
                applied = apply_selection(home, project, run_id=run_id)
                paths = GuardianPaths(home)
                targets = {
                    "authority": paths.personal_profile_authority(applied["profileId"]),
                    "profile": profile_path(home, applied["profileId"]),
                    "snapshot": paths.snapshots(applied["profileId"])
                    / f"{applied['snapshotId']}.json",
                    "current-pointer": paths.profile(applied["profileId"])
                    / "current-snapshot.json",
                }
                targets[kind].unlink()
                before = file_state(home)

                with self.subTest(kind=kind), self.assertRaises(PersonalSelectionError):
                    inspect_personal_selection(home, run_id=run_id)

                self.assertEqual(file_state(home), before)
                if kind == "current-pointer":
                    self.assertFalse(targets[kind].exists())

    def test_apply_recovers_an_interrupted_personal_snapshot_promotion(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.personal_selection import (
            apply_personal_selection,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            discovery = personal_discovery(project)
            preview = prepare_selection_preview(
                home,
                run_id="run-recover",
                discovery=discovery,
            )
            request = permitted_selection(preview, discovery)

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = apply_personal_selection(home, request)

            paths = GuardianPaths(home)
            selection_path = paths.personal_task_selection("run-recover")
            pointer_path = paths.profile(first["profileId"]) / "current-snapshot.json"
            selection_path.unlink()
            pointer_path.unlink()
            self.assertTrue(any(paths.snapshots(first["profileId"]).iterdir()))
            self.assertFalse(pointer_path.exists())

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                recovered = apply_personal_selection(home, request)

            self.assertEqual(recovered["status"], "allowed")
            self.assertTrue(recovered["localChangesPerformed"])
            self.assertEqual(recovered["snapshotId"], first["snapshotId"])
            self.assertEqual(recovered["catalogDigest"], first["catalogDigest"])
            self.assertEqual(recovered["selectionDigest"], first["selectionDigest"])
            self.assertTrue(pointer_path.is_file())
            self.assertTrue(selection_path.is_file())


if __name__ == "__main__":
    unittest.main()

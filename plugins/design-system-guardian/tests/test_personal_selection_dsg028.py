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

    return {
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


if __name__ == "__main__":
    unittest.main()

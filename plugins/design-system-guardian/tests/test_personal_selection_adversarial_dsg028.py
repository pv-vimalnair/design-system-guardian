from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from tests.test_personal_selection_dsg028 import personal_discovery, permitted_selection


class PersonalSelectionAdversarialTest(unittest.TestCase):
    def test_excluded_library_token_provenance_is_rejected_before_writes(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            apply_personal_selection,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            discovery = personal_discovery(project)
            discovery["catalog"]["tokenProvenance"].update(
                {"source": "figma-community-kit", "sourceVersion": "8"}
            )
            preview = prepare_selection_preview(
                home, run_id="excluded-token-source", discovery=discovery
            )

            with self.assertRaisesRegex(PersonalSelectionError, "outside selected libraries"):
                apply_personal_selection(home, permitted_selection(preview, discovery))
            self.assertFalse(home.exists())

    def test_exact_retry_rejects_orphaned_personal_authority(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            apply_personal_selection,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            discovery = personal_discovery(project)
            preview = prepare_selection_preview(
                home,
                run_id="orphaned-exact-retry",
                discovery=discovery,
            )
            request = permitted_selection(preview, discovery)
            applied = apply_personal_selection(home, request)
            authority = GuardianPaths(home).personal_profile_authority(
                applied["profileId"]
            )
            authority.unlink()

            with self.assertRaisesRegex(PersonalSelectionError, "authority"):
                apply_personal_selection(home, request)

            self.assertFalse(authority.exists())
            self.assertTrue(
                GuardianPaths(home).personal_task_selection("orphaned-exact-retry").is_file()
            )

    def test_injected_token_without_exact_readback_is_rejected_before_writes(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            discovery = personal_discovery(project)
            discovery["catalog"]["tokens"]["invented"] = {
                "$type": "dimension",
                "$value": {"value": 13, "unit": "px"},
                "$extensions": {
                    "guardian.figma": {
                        "bindingType": "variable",
                        "fileKey": "figma-brand",
                        "sourceVersion": "42",
                        "key": "invented-variable-key",
                        "collectionKey": "collection-key-space",
                        "resolvedType": "FLOAT",
                    }
                },
            }

            with self.assertRaisesRegex(
                PersonalSelectionError,
                "one-to-one",
            ):
                prepare_selection_preview(
                    home,
                    run_id="invented-token",
                    discovery=discovery,
                )
            self.assertFalse(home.exists())

    def test_injected_component_or_icon_without_exact_readback_is_rejected(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            prepare_selection_preview,
        )

        for plural, identity, node_id, asset_key in (
            ("components", "invented.component", "91:92", "invented-component-key"),
            ("icons", "invented.icon", "93:94", "invented-icon-key"),
        ):
            with self.subTest(kind=plural), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "project"
                project.mkdir()
                home = root / "guardian-home"
                discovery = personal_discovery(project)
                source = discovery["catalog"]["registry"][plural][0]
                invented = copy.deepcopy(source)
                invented["identity"] = identity
                invented["figma"]["nodeId"] = node_id
                invented["figma"]["assetKey"] = asset_key
                discovery["catalog"]["registry"][plural].append(invented)

                with self.assertRaisesRegex(
                    PersonalSelectionError,
                    "one-to-one",
                ):
                    prepare_selection_preview(
                        home,
                        run_id=f"invented-{plural}",
                        discovery=discovery,
                    )
                self.assertFalse(home.exists())

    def test_token_value_change_without_matching_content_digest_is_rejected(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            prepare_selection_preview,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            discovery = personal_discovery(project)
            discovery["catalog"]["tokens"]["color"]["action"]["primary"]["$value"][
                "components"
            ] = [1, 0, 0]

            with self.assertRaisesRegex(
                PersonalSelectionError,
                "value, mode, type, or metadata",
            ):
                prepare_selection_preview(
                    home,
                    run_id="mutated-token-value",
                    discovery=discovery,
                )
            self.assertFalse(home.exists())

    def test_asset_contract_or_code_mapping_change_is_rejected(self) -> None:
        from guardian_core.personal_selection import (
            PersonalSelectionError,
            prepare_selection_preview,
        )

        mutations = {
            "variants": lambda asset: asset["variants"].append("invented"),
            "properties": lambda asset: asset["properties"].update(
                {"tone": ["invented"]}
            ),
            "codeMappings": lambda asset: asset["codeMappings"][0].update(
                {"symbol": "InventedButton.primary"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "project"
                project.mkdir()
                home = root / "guardian-home"
                discovery = personal_discovery(project)
                mutate(discovery["catalog"]["registry"]["components"][0])

                with self.assertRaisesRegex(
                    PersonalSelectionError,
                    "variants, properties, or code mappings",
                ):
                    prepare_selection_preview(
                        home,
                        run_id=f"mutated-asset-{label}",
                        discovery=discovery,
                    )
                self.assertFalse(home.exists())

    def test_personal_snapshot_recovery_holds_profile_transaction_lock(self) -> None:
        from unittest.mock import patch

        from guardian_core.catalog_authority import _load_current_personal_snapshot
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import load_snapshot
        from tests.test_personal_selection_dsg028 import apply_selection

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            applied = apply_selection(home, project, run_id="locked-recovery")
            paths = GuardianPaths(home)
            pointer = paths.profile(applied["profileId"]) / "current-snapshot.json"
            pointer.unlink()
            lock_observed: list[bool] = []

            def guarded_load(*args, **kwargs):
                lock_observed.append(
                    (
                        paths.profile(applied["profileId"]) / "transaction.lock"
                    ).is_file()
                )
                return load_snapshot(*args, **kwargs)

            with patch(
                "guardian_core.snapshot.load_snapshot",
                side_effect=guarded_load,
            ):
                recovered = _load_current_personal_snapshot(
                    home,
                    applied["profileId"],
                )

            self.assertEqual(recovered["snapshotId"], applied["snapshotId"])
            self.assertEqual(lock_observed, [True])
            self.assertTrue(pointer.is_file())

    def test_read_only_run_pin_load_never_repairs_missing_pointer(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.preflight import (
            PreflightError,
            load_run_pin,
            preflight_snapshot,
        )
        from tests.test_onboarding_dsg017 import file_state
        from tests.test_personal_selection_dsg028 import apply_selection

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            home = root / "guardian-home"
            applied = apply_selection(home, project, run_id="pin-no-repair")
            preflight_snapshot(
                home,
                profile_id=applied["profileId"],
                run_id="pin-no-repair",
                policy_digest=applied["policyDigest"],
                project_root=project,
            )
            pointer = (
                GuardianPaths(home).profile(applied["profileId"])
                / "current-snapshot.json"
            )
            pointer.unlink()
            before = file_state(home)

            with self.assertRaises(PreflightError):
                load_run_pin(
                    home,
                    profile_id=applied["profileId"],
                    run_id="pin-no-repair",
                )

            self.assertEqual(file_state(home), before)
            self.assertFalse(pointer.exists())

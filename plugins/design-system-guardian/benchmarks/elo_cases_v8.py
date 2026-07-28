"""Immutable additive v0.3.8 cases for Guardian weighted Elo.

The module uses only Python's standard library and privacy-safe synthetic
inputs. Company catalogs, task selections, local scores, results, and history
remain outside this public benchmark suite.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def _target_import(root: Path) -> Iterator[None]:
    assert (root / "guardian_core").is_dir()
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))
        for name in tuple(sys.modules):
            if name == "guardian_core" or name.startswith("guardian_core."):
                sys.modules.pop(name, None)


def _support() -> object:
    return importlib.import_module("tests.test_personal_selection_dsg028")


def _patch() -> object:
    return importlib.import_module("unittest.mock").patch


def case_correctness_personal_selection_exact_partition(root: Path) -> None:
    with _target_import(root):
        support = _support()
        profile_module = importlib.import_module("guardian_core.profile")
        snapshot_module = importlib.import_module("guardian_core.snapshot")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            applied = support.apply_selection(home, project)
            profile = profile_module.load_profile(home, applied["profileId"])
            snapshot = snapshot_module.load_snapshot(
                home,
                applied["profileId"],
                applied["snapshotId"],
            )
            assert [
                item["fileKey"]
                for item in profile["figma"]["allowlistedLibraryFiles"]
            ] == ["figma-brand", "figma-product"]
            source_keys = {
                item["fileKey"] for item in snapshot["sourceCut"]["figmaFiles"]
            }
            assert support.UNSELECTED_FILE not in source_keys
            assert applied["authorityMode"] == "personal_local"


def case_correctness_personal_preflight_v2_binding(root: Path) -> None:
    with _target_import(root):
        support = _support()
        preflight = importlib.import_module("guardian_core.preflight")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            applied = support.apply_selection(home, project, run_id="run-v8")
            with _patch()("guardian_core.preflight._utc_now", return_value=support.NOW):
                result = preflight.preflight_snapshot(
                    home,
                    profile_id=applied["profileId"],
                    run_id="run-v8",
                    policy_digest=applied["policyDigest"],
                    project_root=project,
                )
            pin = result["pin"]
            assert pin["schemaVersion"] == 2
            assert pin["selectionDigest"] == applied["selectionDigest"]
            assert pin["targetFigmaFile"]["fileKey"] == support.TARGET_FILE
            assert pin["excludedLibraryFileKeys"] == [support.UNSELECTED_FILE]


def case_reliability_new_run_requires_selection(root: Path) -> None:
    with _target_import(root):
        support = _support()
        selection = importlib.import_module("guardian_core.personal_selection")
        preflight = importlib.import_module("guardian_core.preflight")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            applied = support.apply_selection(home, project, run_id="run-one")
            assert selection.inspect_personal_selection(
                home,
                run_id="run-two",
            )["status"] == "selection_required"
            rejected = False
            with _patch()("guardian_core.preflight._utc_now", return_value=support.NOW):
                try:
                    preflight.preflight_snapshot(
                        home,
                        profile_id=applied["profileId"],
                        run_id="run-two",
                        policy_digest=applied["policyDigest"],
                        project_root=project,
                    )
                except preflight.PreflightError:
                    rejected = True
            assert rejected


def case_reliability_permission_drift_rejected(root: Path) -> None:
    with _target_import(root):
        support = _support()
        selection = importlib.import_module("guardian_core.personal_selection")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            discovery = support.personal_discovery(project)
            preview = selection.prepare_selection_preview(
                home,
                run_id="run-bound",
                discovery=discovery,
            )
            changed = copy.deepcopy(discovery)
            changed["candidates"][0]["version"] = "changed-version"
            request = support.permitted_selection(preview, changed)
            rejected = False
            try:
                selection.apply_personal_selection(home, request)
            except selection.PersonalSelectionError:
                rejected = True
            assert rejected
            assert not home.exists()


def case_safety_unknown_source_rejected(root: Path) -> None:
    with _target_import(root):
        support = _support()
        selection = importlib.import_module("guardian_core.personal_selection")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            discovery = support.personal_discovery(project)
            discovery["catalog"]["sourceCut"]["figmaFiles"].append(
                {"fileKey": "synthetic-unknown-source", "version": "1"}
            )
            preview = selection.prepare_selection_preview(
                home,
                run_id="run-unknown",
                discovery=discovery,
            )
            rejected = False
            try:
                selection.apply_personal_selection(
                    home,
                    support.permitted_selection(preview, discovery),
                )
            except selection.PersonalSelectionError:
                rejected = True
            assert rejected
            assert not home.exists()


def case_safety_personal_selection_privacy_gate(root: Path) -> None:
    checker_path = root.parents[1] / "scripts" / "check_public_release.py"
    spec = importlib.util.spec_from_file_location(
        "guardian_synthetic_release_checker_v8",
        checker_path,
    )
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = checker
    try:
        spec.loader.exec_module(checker)
        assert (
            "plugins/design-system-guardian/personal/"
            in checker.RUNTIME_PREFIXES
        )
        assert {
            "selectionDigest",
            "selectionSetDigest",
            "permissionBindingDigest",
            "discoveryDigest",
            "projectBindingDigest",
        }.issubset(checker.IDENTIFIER_KEYS)
        identifiers = set(
            checker._walk_identifiers(
                {
                    "selectedLibraryFileKeys": ["synthetic-selected-library"],
                    "excludedLibraryFileKeys": ["synthetic-excluded-library"],
                }
            )
        )
        assert identifiers == {
            "synthetic-selected-library",
            "synthetic-excluded-library",
        }
        runtime = json.dumps(
            {
                "runId": "synthetic-run",
                "selectionDigest": "a" * 64,
                "targetFigmaFile": {
                    "fileKey": "synthetic-working-file",
                    "version": "1",
                },
            }
        ).encode("utf-8")
        assert checker._runtime_json(
            runtime,
            "plugins/design-system-guardian/docs/synthetic-selection.json",
        )
    finally:
        sys.modules.pop(spec.name, None)


def case_coverage_enterprise_preflight_stays_v1(root: Path) -> None:
    with _target_import(root):
        support = _support()
        fixture = importlib.import_module("tests.guardian_test_support")
        profile_data = importlib.import_module("tests.test_profile_snapshot")
        preflight = importlib.import_module("guardian_core.preflight")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            project.mkdir()
            snapshot = fixture.ingest_test_snapshot(
                home,
                profile_data.sample_profile(),
                profile_data.sample_catalog(),
                now=profile_data.NOW,
            )
            with _patch()(
                "guardian_core.preflight._utc_now",
                return_value=profile_data.NOW,
            ):
                result = preflight.preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-enterprise-v1",
                    policy_digest=snapshot["policyDigest"],
                    project_root=project,
                )
            assert result["pin"]["schemaVersion"] == 1
            assert "authorityMode" not in result["pin"]
            assert "selectionDigest" not in result["pin"]


def case_portability_selection_cli_and_two_skills(root: Path) -> None:
    with _target_import(root):
        cli = importlib.import_module("guardian_core.cli")
        parser = cli.build_parser()
        command_action = next(
            action
            for action in parser._actions
            if getattr(action, "dest", None) == "command"
        )
        assert "selection" in command_action.choices
        selection_parser = command_action.choices["selection"]
        selection_action = next(
            action
            for action in selection_parser._actions
            if getattr(action, "dest", None) == "selection_command"
        )
        assert set(selection_action.choices) == {"status", "preview", "apply"}
        skills = {
            path.name
            for path in (root / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        assert skills == {"audit-design-system", "build-with-design-system"}

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_personal_selection_dsg028 import (
    personal_discovery,
    permitted_selection,
)
from tests.test_profile_snapshot import NOW


class GuardianPersonalSelectionCliTest(unittest.TestCase):
    def test_status_preview_permission_apply_and_status_form_one_local_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            discovery = personal_discovery(project)
            discovery_path = root / "discovery.json"
            write_canonical(discovery_path, discovery)

            code, status = invoke(home, ["selection", "status", "--run-id", "run-cli"])
            self.assertEqual(code, 4)
            self.assertEqual(status["status"], "selection_required")
            self.assertFalse(home.exists())

            code, preview = invoke(
                home,
                [
                    "selection",
                    "preview",
                    "--run-id",
                    "run-cli",
                    "--input",
                    str(discovery_path),
                ],
            )
            self.assertEqual(code, 4)
            self.assertEqual(preview["status"], "permission_required")
            self.assertEqual(preview["authorityMode"], "personal_local")
            self.assertEqual(
                preview["selectedLibraryFileKeys"],
                ["figma-brand", "figma-product"],
            )
            self.assertEqual(
                preview["excludedLibraryFileKeys"],
                ["figma-community-kit"],
            )
            self.assertFalse(home.exists())

            request_path = root / "permitted-selection.json"
            write_canonical(request_path, permitted_selection(preview, discovery))
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                code, applied = invoke(
                    home,
                    ["selection", "apply", "--input", str(request_path)],
                )
            self.assertEqual(code, 0)
            self.assertEqual(applied["status"], "allowed")
            self.assertEqual(applied["authorityMode"], "personal_local")

            before = {
                path.relative_to(home).as_posix(): path.read_bytes()
                for path in home.rglob("*")
                if path.is_file()
            }
            code, ready = invoke(home, ["selection", "status", "--run-id", "run-cli"])
            self.assertEqual(code, 0)
            self.assertEqual(ready["status"], "allowed")
            self.assertEqual(ready["selectionDigest"], applied["selectionDigest"])
            after = {
                path.relative_to(home).as_posix(): path.read_bytes()
                for path in home.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_cli_rejects_incomplete_discovery_and_empty_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            cases = []

            incomplete = personal_discovery(project)
            incomplete["discoveryComplete"] = False
            cases.append(("incomplete", incomplete))
            empty = personal_discovery(project)
            for candidate in empty["candidates"]:
                candidate["decision"] = "do_not_use"
            cases.append(("empty", empty))

            for name, discovery in cases:
                home = root / f"home-{name}"
                path = root / f"{name}.json"
                write_canonical(path, discovery)
                code, result = invoke(
                    home,
                    [
                        "selection",
                        "preview",
                        "--run-id",
                        f"run-{name}",
                        "--input",
                        str(path),
                    ],
                )
                with self.subTest(name=name):
                    self.assertEqual(code, 2)
                    self.assertEqual(result["status"], "invalid")
                    self.assertFalse(home.exists())


if __name__ == "__main__":
    unittest.main()

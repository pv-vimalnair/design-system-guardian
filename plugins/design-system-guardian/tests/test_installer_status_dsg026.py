from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cross_agent_packaging import installer_module, load_json, write_json


class InstallerStatusTest(unittest.TestCase):
    @staticmethod
    def _successful_runner(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    @staticmethod
    def _tree_bytes(root: Path) -> dict[str, bytes]:
        if not root.exists():
            return {}
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def test_status_is_zero_write_and_distinguishes_current_update_and_invalid(self) -> None:
        module = installer_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "skills"
            before = self._tree_bytes(target)
            missing = module.installation_status(target)
            self.assertEqual(missing["status"], "update_required")
            self.assertEqual(missing["reasonCode"], "guardian_not_installed")
            self.assertEqual(self._tree_bytes(target), before)
            self.assertFalse(target.exists())

            module.install(
                target,
                Path(sys.executable).resolve(),
                False,
                runtime_runner=self._successful_runner,
            )
            installed = self._tree_bytes(target)
            current = module.installation_status(target)
            self.assertEqual(current["status"], "current")
            self.assertEqual(current["reasonCode"], "exact_package_installed")
            self.assertEqual(self._tree_bytes(target), installed)

            for name in module.SKILL_NAMES:
                path = target / name / module.BINDING_RELATIVE
                binding = load_json(path)
                binding["pluginVersion"] = "0.3.4"
                write_json(path, binding)
            update = module.installation_status(target)
            self.assertEqual(update["status"], "update_required")
            self.assertEqual(update["reasonCode"], "older_intact_installation")

            path = target / module.SKILL_NAMES[0] / module.BINDING_RELATIVE
            binding = load_json(path)
            binding["pluginVersion"] = "0.3.6"
            write_json(path, binding)
            invalid = module.installation_status(target)
            self.assertEqual(invalid["status"], "invalid")
            self.assertEqual(invalid["reasonCode"], "divergent_plugin_versions")

    def test_status_cli_requires_no_python_and_emits_canonical_json(self) -> None:
        module = installer_module()
        installer = module.PLUGIN_ROOT / "scripts" / "install_agent_skills.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "missing"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(installer),
                    "--target-root",
                    str(target),
                    "--status",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "update_required")
            self.assertEqual(
                completed.stdout,
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            )
            self.assertFalse(target.exists())

    def test_windows_watched_root_failure_rolls_back_before_reload_result(self) -> None:
        module = installer_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "skills"
            module.install(
                target,
                Path(sys.executable).resolve(),
                False,
                runtime_runner=self._successful_runner,
            )
            before = self._tree_bytes(target)
            original_rename = Path.rename
            promotion_attempts = 0

            def locked_once(path: Path, destination: Path) -> Path:
                nonlocal promotion_attempts
                if path.parent.name.startswith(".design-system-guardian-stage-"):
                    promotion_attempts += 1
                    if promotion_attempts == 1:
                        error = PermissionError("watched directory")
                        error.winerror = 32  # type: ignore[attr-defined]
                        raise error
                return original_rename(path, destination)

            with (
                mock.patch.object(module, "_is_windows_host_lock", return_value=True),
                mock.patch.object(Path, "rename", new=locked_once),
                self.assertRaises(module.HostRestartRequired) as caught,
            ):
                module.install(
                    target,
                    Path(sys.executable).resolve(),
                    True,
                    runtime_runner=self._successful_runner,
                )

            self.assertEqual(caught.exception.status, "reload_required")
            self.assertEqual(caught.exception.reason_code, "host_restart_required")
            self.assertEqual(caught.exception.target_root, target.resolve())
            self.assertEqual(self._tree_bytes(target), before)
            self.assertFalse((target / module.JOURNAL_NAME).exists())

    def test_reload_result_is_not_emitted_when_rollback_cannot_be_verified(self) -> None:
        module = installer_module()
        locked = PermissionError("watched directory")
        locked.winerror = 32  # type: ignore[attr-defined]
        with (
            mock.patch.object(module, "_is_windows_host_lock", return_value=True),
            mock.patch.object(module, "recover_interrupted", side_effect=module.InstallError("rollback failed")),
            self.assertRaisesRegex(module.InstallError, "recovery evidence was preserved"),
        ):
            module._recover_install_failure(Path("C:/guardian-skills"), locked)


if __name__ == "__main__":
    unittest.main()

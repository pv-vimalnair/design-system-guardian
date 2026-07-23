from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class GuardianLauncherSecurityTests(unittest.TestCase):
    def test_windows_convenience_launcher_never_uses_ambient_python(self) -> None:
        launcher = (PLUGIN_ROOT / "scripts" / "guardian.cmd").read_text(
            encoding="utf-8"
        )
        lowered = launcher.lower()
        self.assertNotIn("python ", lowered)
        self.assertNotIn("python.exe", lowered)
        self.assertIn("exit /b 4", lowered)
        self.assertIn("host-pinned", lowered)

    def test_posix_convenience_launcher_never_uses_ambient_python(self) -> None:
        launcher = (PLUGIN_ROOT / "scripts" / "guardian").read_text(
            encoding="utf-8"
        )
        lowered = launcher.lower()
        self.assertNotIn("python3", lowered)
        self.assertNotIn("/usr/bin/env", lowered)
        self.assertIn("exit 4", lowered)
        self.assertIn("host-pinned", lowered)
        self.assertNotIn(b"\r", (PLUGIN_ROOT / "scripts" / "guardian").read_bytes())

    @unittest.skipUnless(__import__("os").name == "nt", "Windows launcher test")
    def test_windows_convenience_launcher_fails_closed(self) -> None:
        completed = subprocess.run(
            [str(PLUGIN_ROOT / "scripts" / "guardian.cmd"), "doctor"],
            cwd=PLUGIN_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 4)
        self.assertIn("host-pinned", (completed.stdout + completed.stderr).lower())
        self.assertNotIn('"status":"allowed"', completed.stdout.lower())


if __name__ == "__main__":
    unittest.main()

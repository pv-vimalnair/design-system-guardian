from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class PublicationPrivacyTests(unittest.TestCase):
    def test_tracked_source_has_no_pilot_company_name_variants(self) -> None:
        variants = (
            "monie" + "point",
            "Monie" + "point",
            "Monie" + "Point",
        )
        command = ["git", "grep", "-I", "-n"]
        for variant in variants:
            command.extend(["-e", variant])
        command.extend(["--", "plugins/design-system-guardian"])
        result = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            self.fail(f"pilot-company text remains in tracked source:\n{result.stdout}")
        if result.returncode > 1:
            self.fail(f"git grep failed with {result.returncode}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


def host_platform_id() -> str:
    operating_system = {
        "win32": "windows",
        "linux": "linux",
        "darwin": "macos",
    }[sys.platform]
    architecture = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }[platform.machine().lower()]
    return f"{operating_system}-{architecture}"


def bound_flutter_profile() -> dict:
    profile = sample_profile()
    profile["adapters"]["flutter"] = {
        "enabled": True,
        "platformArtifacts": {
            host_platform_id(): {
                "dartSdk": {
                    "contentDigest": "d" * 64,
                    "executableRelativePath": "bin/dart.exe"
                    if sys.platform == "win32"
                    else "bin/dart",
                }
            }
        },
        "requiredPackages": {
            "flutter": {
                "contentDigest": "f" * 64,
                "repositoryCommit": "c" * 40,
            }
        },
    }
    return profile


class FlutterProfileAuthorityTests(unittest.TestCase):
    def test_enabled_flutter_profile_requires_exact_toolchain_and_framework_bindings(self) -> None:
        from guardian_core.profile import ProfileValidationError, validate_profile

        for malformed in (
            {"enabled": True},
            {
                "enabled": True,
                "platformArtifacts": {},
                "requiredPackages": {},
            },
            {
                "enabled": True,
                "platformArtifacts": {
                    host_platform_id(): {
                        "dartSdk": {
                            "contentDigest": "d" * 64,
                            "executableRelativePath": "../dart",
                        }
                    }
                },
                "requiredPackages": {
                    "flutter": {
                        "contentDigest": "f" * 64,
                        "repositoryCommit": "short",
                    }
                },
            },
        ):
            profile = sample_profile()
            profile["adapters"]["flutter"] = malformed
            with self.subTest(malformed=malformed), self.assertRaises(
                ProfileValidationError
            ):
                validate_profile(profile)

    def test_run_bound_config_copies_only_current_profile_platform_authority(self) -> None:
        from guardian_core.flutter_config import _generate_flutter_adapter_config_at_home
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = bound_flutter_profile()
            catalog = sample_catalog()
            for collection in ("components", "icons"):
                for asset in catalog["registry"][collection]:
                    for mapping in asset["codeMappings"]:
                        mapping["framework"] = "not-flutter"
            snapshot = ingest_test_snapshot(
                home, profile, catalog, now=NOW
            )
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id=profile["profileId"],
                    run_id="profile-authority",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )
            config = _generate_flutter_adapter_config_at_home(
                home,
                profile_id=profile["profileId"],
                run_id="profile-authority",
            )

        expected_artifact = profile["adapters"]["flutter"]["platformArtifacts"][
            host_platform_id()
        ]
        self.assertEqual(
            config["toolchain"],
            {
                "platformId": host_platform_id(),
                "dartSdk": expected_artifact["dartSdk"],
            },
        )
        self.assertEqual(
            config["requiredPackages"],
            profile["adapters"]["flutter"]["requiredPackages"],
        )
        self.assertNotIn("platformArtifacts", config)


if __name__ == "__main__":
    unittest.main()

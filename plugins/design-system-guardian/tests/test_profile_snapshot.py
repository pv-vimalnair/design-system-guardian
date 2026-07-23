

import tempfile
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.guardian_test_support import ingest_test_snapshot, install_test_context


NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


def _host_platform_id() -> str:
    operating_system = {"win32": "windows", "linux": "linux", "darwin": "macos"}[sys.platform]
    architecture = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }[platform.machine().lower()]
    return f"{operating_system}-{architecture}"


def sample_profile(profile_id: str = "example-company") -> dict:
    return {
        "schemaVersion": 1,
        "profileId": profile_id,
        "displayName": "Example Company",
        "figma": {
            "allowlistedLibraryFiles": [
                {"fileKey": "figma-brand", "name": "Brand library"},
                {"fileKey": "figma-product", "name": "Product library"},
            ]
        },
        "adapters": {
            "flutter": {
                "enabled": True,
                "platformArtifacts": {
                    _host_platform_id(): {
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
        },
    }


def sample_catalog(profile_id: str = "example-company") -> dict:
    return {
        "schemaVersion": 1,
        "profileId": profile_id,
        "createdAt": "2026-07-15T11:00:00Z",
        "refreshAttemptedAt": "2026-07-15T11:00:00Z",
        "lastSuccessfulRefreshAt": "2026-07-15T11:00:00Z",
        "sourceAvailable": True,
        "sourceComplete": True,
        "sourceEvidence": {
            "refreshAttempted": True,
            "figmaVariables": {
                "used": True,
                "valuesPresent": True,
                "modesPresent": True,
            },
        },
        "sourceCut": {
            "figmaFiles": [
                {"fileKey": "figma-brand", "version": "42"},
                {"fileKey": "figma-product", "version": "91"},
            ],
            "codeConnectParseDigest": "b" * 64,
            "repositoryCommit": "abc1234",
            "componentCatalogBuild": "catalog-2026.07.15",
        },
        "tokenProvenance": {
            "approval": "explicit",
            "source": "canonical_dtcg",
            "sourceVersion": "tokens-42",
            "published": True,
        },
        "tokens": {
            "color": {
                "$type": "color",
                "action": {
                    "primary": {
                        "$value": {
                            "colorSpace": "srgb",
                            "components": [0.1, 0.2, 0.3],
                            "alpha": 1,
                        }
                    }
                },
            },
            "space": {
                "$type": "dimension",
                "200": {"$value": {"value": 8, "unit": "px"}},
            },
        },
        "resolver": {
            "version": "2025.10",
            "modifiers": {
                "theme": {"contexts": {"light": [], "dark": []}, "default": "light"}
            },
            "resolutionOrder": [{"$ref": "#/modifiers/theme"}],
        },
        "resolverContext": {"theme": "light"},
        "registry": {
            "components": [
                {
                    "identity": "button.primary",
                    "status": "approved",
                    "sourceVersion": "42",
                    "figma": {
                        "fileKey": "figma-brand",
                        "nodeId": "1:2",
                        "assetKey": "component-key-primary",
                        "published": True,
                    },
                    "variants": ["default", "loading"],
                    "properties": {"size": ["small", "medium", "large"]},
                    "codeMappings": [
                        {
                            "framework": "flutter",
                            "symbol": "MpButton.primary",
                            "approved": True,
                            "inferred": False,
                            "sourceDigest": "c" * 64,
                        }
                    ],
                }
            ],
            "icons": [
                {
                    "identity": "icon.check",
                    "status": "approved",
                    "sourceVersion": "91",
                    "figma": {
                        "fileKey": "figma-product",
                        "nodeId": "5:9",
                        "assetKey": "icon-key-check",
                        "published": True,
                    },
                    "variants": ["default"],
                    "properties": {},
                    "codeMappings": [
                        {
                            "framework": "flutter",
                            "symbol": "MpIcons.check",
                            "approved": True,
                            "inferred": False,
                            "sourceDigest": "d" * 64,
                        }
                    ],
                }
            ],
        },
    }


class ProfileContractTest(unittest.TestCase):
    def test_profile_validates_installs_and_loads_canonically(self) -> None:
        from guardian_core.profile import install_profile, load_profile, validate_profile

        profile = validate_profile(sample_profile())
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = install_profile(home, profile)
            self.assertEqual(path, home / "profiles" / "example-company" / "profile.json")
            self.assertEqual(load_profile(home, "example-company"), profile)

    def test_profile_rejects_unknown_fields_and_duplicate_library_keys(self) -> None:
        from guardian_core.profile import ProfileValidationError, validate_profile

        unknown = {**sample_profile(), "otherCompany": {}}
        duplicate = sample_profile()
        duplicate["figma"]["allowlistedLibraryFiles"].append(
            {"fileKey": "figma-brand", "name": "duplicate"}
        )
        for profile in (unknown, duplicate):
            with self.subTest(profile=profile), self.assertRaises(ProfileValidationError):
                validate_profile(profile)


class SnapshotContractTest(unittest.TestCase):
    def test_ingest_is_immutable_idempotent_and_profile_isolated(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            install_test_context(home, profile)
            first = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW)
            second = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW)
            self.assertEqual(first["snapshotId"], second["snapshotId"])
            self.assertEqual(first["sourceState"], "fresh")
            self.assertEqual(first, load_snapshot(home, "example-company", first["snapshotId"]))
            self.assertEqual(first["sourceCut"]["catalogDigest"], first["catalogDigest"])
            self.assertIn("button.primary", [item["identity"] for item in first["registry"]["components"]])

            with self.assertRaises(SnapshotValidationError):
                ingest_test_snapshot(home, profile, sample_catalog("other-company"), now=NOW)

    def test_source_outage_incomplete_and_stale_remain_distinct(self) -> None:
        from guardian_core.snapshot import classify_source_state

        cases = [
            ({"sourceAvailable": False, "lastSuccessfulRefreshAt": "2026-07-13T12:00:00Z", "sourceComplete": True}, "offline_grace"),
            ({"sourceAvailable": False, "lastSuccessfulRefreshAt": "2026-07-12T04:00:00Z", "sourceComplete": True}, "source_unavailable"),
            ({"sourceAvailable": False, "lastSuccessfulRefreshAt": "2026-07-07T11:59:59Z", "sourceComplete": True}, "stale"),
            ({"sourceAvailable": True, "lastSuccessfulRefreshAt": "2026-07-15T11:00:00Z", "sourceComplete": False}, "source_incomplete"),
        ]
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(classify_source_state(source, now=NOW)["state"], expected)

    def test_published_variable_metadata_without_values_or_modes_is_incomplete(self) -> None:
        from guardian_core.snapshot import ingest_snapshot

        catalog = sample_catalog()
        catalog["sourceEvidence"]["figmaVariables"]["valuesPresent"] = False
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            install_test_context(home, profile)
            snapshot = ingest_test_snapshot(home, profile, catalog, now=NOW)
            self.assertEqual(snapshot["sourceState"], "source_incomplete")
            self.assertFalse(snapshot["sourceComplete"])

    def test_unpublished_unallowlisted_and_inferred_approved_assets_are_rejected(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot

        mutations = []
        unpublished = sample_catalog()
        unpublished["registry"]["icons"][0]["figma"]["published"] = False
        mutations.append(unpublished)
        unallowlisted = sample_catalog()
        unallowlisted["registry"]["icons"][0]["figma"]["fileKey"] = "community-file"
        mutations.append(unallowlisted)
        inferred = sample_catalog()
        inferred["registry"]["components"][0]["codeMappings"][0]["inferred"] = True
        mutations.append(inferred)

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            install_test_context(home, profile)
            for catalog in mutations:
                with self.subTest(catalog=catalog), self.assertRaises(SnapshotValidationError):
                    ingest_test_snapshot(home, profile, catalog, now=NOW)


if __name__ == "__main__":
    unittest.main()

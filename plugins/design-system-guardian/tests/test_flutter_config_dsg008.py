import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import sample_catalog, sample_profile


NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
EXTENSION = "org.design-system-guardian.code-connect"
LIBRARY = "package:example_company_design_system/example_company_design_system.dart"
COLOR = f"{LIBRARY}#AppColors.primary"
TEXT_STYLE = f"{LIBRARY}#AppTypography.body"
DIMENSION = f"{LIBRARY}#AppSpacing.medium"
EFFECT = f"{LIBRARY}#AppEffects.card"
MOTION = f"{LIBRARY}#AppMotion.standard"
ICON = f"{LIBRARY}#AppIcons.check"
WIDGET = f"{LIBRARY}#MpButton.primary"
VARIANT_PRIMARY = f"{LIBRARY}#MpButtonVariant.primary"
SIZE_SMALL = f"{LIBRARY}#MpButtonSize.small"
SIZE_LARGE = f"{LIBRARY}#MpButtonSize.large"


def mapping(
    symbol: str,
    *,
    framework: str = "flutter",
    approved: bool = True,
    inferred: bool = False,
) -> dict:
    return {
        "framework": framework,
        "symbol": symbol,
        "approved": approved,
        "inferred": inferred,
        "sourceDigest": "e" * 64,
    }


def extension(*mappings: dict) -> dict:
    return {EXTENSION: {"codeMappings": list(mappings)}}


def fully_mapped_catalog() -> dict:
    catalog = sample_catalog()
    catalog["sourceCut"]["repositoryCommit"] = "c" * 40
    catalog["tokens"]["color"]["action"]["primary"]["$extensions"] = extension(
        mapping(COLOR)
    )
    catalog["tokens"]["space"]["200"]["$extensions"] = extension(
        mapping(DIMENSION)
    )
    catalog["tokens"]["text"] = {
        "$type": "typography",
        "$value": {
            "fontFamily": "Inter",
            "fontSize": {"value": 16, "unit": "px"},
            "fontWeight": 400,
            "letterSpacing": {"value": 0, "unit": "px"},
            "lineHeight": 1.5,
        },
        "$extensions": extension(mapping(TEXT_STYLE)),
    }
    catalog["tokens"]["elevation"] = {
        "$type": "shadow",
        "$value": {
            "color": {
                "colorSpace": "srgb",
                "components": [0, 0, 0],
                "alpha": 0.2,
            },
            "offsetX": {"value": 0, "unit": "px"},
            "offsetY": {"value": 2, "unit": "px"},
            "blur": {"value": 4, "unit": "px"},
            "spread": {"value": 0, "unit": "px"},
        },
        "$extensions": extension(mapping(EFFECT)),
    }
    catalog["tokens"]["motion"] = {
        "$type": "duration",
        "$value": {"value": 200, "unit": "ms"},
        "$extensions": extension(mapping(MOTION)),
    }
    component = catalog["registry"]["components"][0]
    component["codeMappings"] = [mapping(WIDGET)]
    component["variants"] = [VARIANT_PRIMARY]
    component["properties"] = {
        "size": [SIZE_SMALL, SIZE_LARGE],
    }
    catalog["registry"]["icons"][0]["codeMappings"] = [mapping(ICON)]
    return catalog


def provision_pin(home: Path, catalog: dict, *, run_id: str = "run-flutter-config", project_root: Path | None = None) -> dict:
    from guardian_core.preflight import preflight_snapshot

    profile = sample_profile()
    snapshot = ingest_test_snapshot(home, profile, catalog, now=NOW)
    with patch("guardian_core.preflight._utc_now", return_value=NOW):
        result = preflight_snapshot(
            home,
            profile_id=profile["profileId"],
            run_id=run_id,
            policy_digest=snapshot["policyDigest"],
            project_root=project_root or home,
        )
    if result["pinCreated"] is not True:
        raise AssertionError("test fixture did not produce a production-eligible pin")
    return result["pin"]


class FlutterConfigGenerationTest(unittest.TestCase):
    def test_generates_only_exact_mapped_identities_and_exact_binding(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.flutter_config import _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_pin(home, fully_mapped_catalog())

            config = generate_flutter_adapter_config(
                home,
                profile_id="example-company",
                run_id="run-flutter-config",
            )

        self.assertEqual(config["schemaVersion"], 1)
        self.assertEqual(config["adapter"], "flutter")
        self.assertEqual(config["adapterVersion"], "0.1.0")
        self.assertEqual(config["profileId"], pin["profileId"])
        self.assertEqual(config["policyDigest"], pin["policyDigest"])
        self.assertEqual(config["snapshotId"], pin["snapshotId"])
        self.assertEqual(config["sourceCutDigest"], sha256_digest(pin["sourceCut"]))
        unsigned = dict(config)
        claimed_digest = unsigned.pop("configDigest")
        self.assertEqual(claimed_digest, sha256_digest(unsigned))
        self.assertEqual(
            config["approvedIdentities"],
            {
                "colors": [COLOR],
                "textStyles": [TEXT_STYLE],
                "icons": [ICON],
                "dimensions": [DIMENSION],
                "effects": [EFFECT],
                "motion": [MOTION],
                "widgets": [WIDGET],
            },
        )
        self.assertEqual(
            config["componentVariants"],
            {
                WIDGET: {
                    "size": sorted([SIZE_SMALL, SIZE_LARGE]),
                    "variant": [VARIANT_PRIMARY],
                }
            },
        )
        self.assertNotIn("value", config["approvedIdentities"])

    def test_ignores_valid_non_flutter_mappings_without_guessing(self) -> None:
        from guardian_core.flutter_config import _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = fully_mapped_catalog()
        catalog["tokens"]["color"]["action"]["primary"]["$extensions"] = extension(
            mapping("@example-company/tokens.colors.primary", framework="react")
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            config = generate_flutter_adapter_config(
                home,
                profile_id="example-company",
                run_id="run-flutter-config",
            )
        self.assertEqual(config["approvedIdentities"]["colors"], [])

    def test_rejects_untrusted_or_noncanonical_flutter_token_mappings(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        cases = {
            "unapproved": mapping(COLOR, approved=False),
            "inferred": mapping(COLOR, inferred=True),
            "noncanonical": mapping("AppColors.primary"),
            "framework-default": mapping("package:flutter/material.dart#Colors.blue"),
            "malformed": {
                "framework": "flutter",
                "symbol": COLOR,
                "approved": True,
                "inferred": False,
            },
        }
        for label, bad_mapping in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                catalog = fully_mapped_catalog()
                catalog["tokens"]["color"]["action"]["primary"]["$extensions"] = extension(
                    bad_mapping
                )
                home = Path(directory)
                provision_pin(home, catalog)
                with self.assertRaises(FlutterConfigError):
                    generate_flutter_adapter_config(
                        home,
                        profile_id="example-company",
                        run_id="run-flutter-config",
                    )

    def test_rejects_flutter_mapping_for_unsupported_token_type(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = fully_mapped_catalog()
        catalog["tokens"]["opacity"] = {
            "$type": "number",
            "$value": 0.5,
            "$extensions": extension(mapping(f"{LIBRARY}#AppOpacity.disabled")),
        }
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            with self.assertRaisesRegex(FlutterConfigError, "unsupported token type"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )

    def test_rejects_deprecated_token_mapping_for_new_code_selection(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = fully_mapped_catalog()
        catalog["tokens"]["color"]["action"]["primary"]["$deprecated"] = "Use color.action.brand"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            with self.assertRaisesRegex(FlutterConfigError, "deprecated"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )


    def test_rejects_identity_ambiguity_across_sources_or_categories(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = fully_mapped_catalog()
        catalog["tokens"]["space"]["200"]["$extensions"] = extension(mapping(COLOR))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            with self.assertRaisesRegex(FlutterConfigError, "ambiguous"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )

    def test_rejects_plain_variant_labels_instead_of_manufacturing_identities(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = fully_mapped_catalog()
        catalog["registry"]["components"][0]["variants"] = ["primary"]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            with self.assertRaisesRegex(FlutterConfigError, "variant"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )

    def test_rejects_unapproved_inferred_or_noncanonical_registry_mapping(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        cases = {
            "unapproved": mapping(WIDGET, approved=False),
            "inferred": mapping(WIDGET, approved=False, inferred=True),
            "noncanonical": mapping("MpButton.primary"),
        }
        for label, bad_mapping in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                catalog = fully_mapped_catalog()
                catalog["registry"]["components"][0]["codeMappings"] = [bad_mapping]
                home = Path(directory)
                provision_pin(home, catalog)
                with self.assertRaises(FlutterConfigError):
                    generate_flutter_adapter_config(
                        home,
                        profile_id="example-company",
                        run_id="run-flutter-config",
                    )

    def test_token_flutter_mapping_requires_pinned_code_connect_provenance(self) -> None:
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config

        catalog = sample_catalog()
        catalog["tokens"]["color"]["action"]["primary"]["$extensions"] = extension(
            mapping(COLOR)
        )
        catalog["registry"]["components"][0]["codeMappings"] = []
        catalog["registry"]["icons"][0]["codeMappings"] = []
        catalog["sourceCut"]["codeConnectParseDigest"] = None
        catalog["sourceCut"]["repositoryCommit"] = None
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, catalog)
            with self.assertRaisesRegex(FlutterConfigError, "Code Connect provenance"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )


    def test_requires_verified_pin_and_enabled_exact_flutter_profile(self) -> None:
        from guardian_core.canonical import atomic_write_json, read_canonical_json
        from guardian_core.flutter_config import FlutterConfigError, _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config
        from guardian_core.paths import GuardianPaths

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, fully_mapped_catalog())
            pin_path = GuardianPaths(home).profile("example-company") / "runs" / "run-flutter-config" / "pin.json"
            pin = read_canonical_json(pin_path)
            pin["snapshotId"] = "0" * 64
            atomic_write_json(pin_path, pin)
            with self.assertRaises(FlutterConfigError):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )

        catalog = fully_mapped_catalog()
        profile = sample_profile()
        profile["adapters"]["flutter"] = {"enabled": False}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            snapshot = ingest_test_snapshot(home, profile, catalog, now=NOW)
            from guardian_core.preflight import preflight_snapshot

            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-disabled",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )
            with self.assertRaisesRegex(FlutterConfigError, "not exactly enabled"):
                generate_flutter_adapter_config(
                    home,
                    profile_id="example-company",
                    run_id="run-disabled",
                )

    def test_public_generator_uses_only_the_canonical_host_trust_root(self) -> None:
        from guardian_core.flutter_config import generate_flutter_adapter_config

        signature = inspect.signature(generate_flutter_adapter_config)
        self.assertNotIn("home", signature.parameters)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, fully_mapped_catalog())
            with patch(
                "guardian_core.flutter_config.default_guardian_home",
                return_value=home,
            ) as canonical_home:
                config = generate_flutter_adapter_config(
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )
            canonical_home.assert_called_once_with()
            self.assertEqual(config["profileId"], "example-company")
            with self.assertRaises(TypeError):
                generate_flutter_adapter_config(
                    home=home,
                    profile_id="example-company",
                    run_id="run-flutter-config",
                )


    def test_explicit_writer_uses_canonical_atomic_json(self) -> None:
        from guardian_core.canonical import canonical_json_bytes
        from guardian_core.flutter_config import (
            _generate_flutter_adapter_config_at_home as generate_flutter_adapter_config,
            write_flutter_adapter_config,
        )

        signature = inspect.signature(write_flutter_adapter_config)
        self.assertIs(signature.parameters["output_path"].default, inspect.Parameter.empty)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            provision_pin(home, fully_mapped_catalog())
            config = generate_flutter_adapter_config(
                home,
                profile_id="example-company",
                run_id="run-flutter-config",
            )
            output = home / "explicit-project" / ".design-system-guardian" / "flutter-adapter.json"
            returned = write_flutter_adapter_config(config, output_path=output)
            self.assertEqual(returned, output)
            self.assertEqual(output.read_bytes(), canonical_json_bytes(config))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), config)
            round_trip = json.loads(output.read_text(encoding="utf-8"))
            second_output = home / "second-project" / "flutter-adapter.json"
            write_flutter_adapter_config(round_trip, output_path=second_output)
            self.assertEqual(second_output.read_bytes(), output.read_bytes())


if __name__ == "__main__":
    unittest.main()

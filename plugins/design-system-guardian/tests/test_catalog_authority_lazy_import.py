import importlib.metadata
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import call, patch

from tests.catalog_authority_test_support import attest_catalog
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class CatalogAuthorityLazyImportTest(unittest.TestCase):
    def test_production_module_import_does_not_require_cryptography(self) -> None:
        plugin_root = Path(__file__).resolve().parents[1]
        script = """
import builtins

real_import = builtins.__import__

def reject_cryptography(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "cryptography" or name.startswith("cryptography."):
        raise ModuleNotFoundError("cryptography deliberately unavailable")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = reject_cryptography
import guardian_core.catalog_authority
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=plugin_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_dependency_loads_all_verification_components_dynamically(self) -> None:
        from guardian_core import catalog_authority

        serialization = types.SimpleNamespace()
        public_key_type = type("PublicKey", (), {})
        invalid_signature = type("SignatureFailure", (Exception,), {})
        modules = {
            "cryptography.hazmat.primitives.serialization": serialization,
            "cryptography.hazmat.primitives.asymmetric.ed25519": types.SimpleNamespace(
                Ed25519PublicKey=public_key_type
            ),
            "cryptography.exceptions": types.SimpleNamespace(InvalidSignature=invalid_signature),
        }

        with (
            patch("importlib.metadata.version", return_value="46.0.7"),
            patch("importlib.import_module", side_effect=modules.__getitem__) as dynamic_import,
        ):
            self.assertEqual(catalog_authority.verify_runtime_dependency(), "46.0.7")

        self.assertEqual(
            dynamic_import.call_args_list,
            [
                call("cryptography.hazmat.primitives.serialization"),
                call("cryptography.hazmat.primitives.asymmetric.ed25519"),
                call("cryptography.exceptions"),
            ],
        )

    def test_runtime_dependency_converts_missing_import_and_version_errors(self) -> None:
        from guardian_core import catalog_authority

        cases = (
            (
                patch(
                    "importlib.metadata.version",
                    side_effect=importlib.metadata.PackageNotFoundError("cryptography"),
                ),
                patch("importlib.import_module"),
                "is not installed",
            ),
            (
                patch("importlib.metadata.version", return_value="46.0.8"),
                patch("importlib.import_module"),
                "must be exactly 46.0.7",
            ),
            (
                patch("importlib.metadata.version", return_value="46.0.7"),
                patch("importlib.import_module", side_effect=ImportError("broken wheel")),
                "cannot be imported",
            ),
        )

        for version_patch, import_patch, message in cases:
            with self.subTest(message=message), version_patch, import_patch:
                with self.assertRaisesRegex(catalog_authority.CatalogAuthorityError, message):
                    catalog_authority.verify_runtime_dependency()

    def test_sequence_above_signed_64_bit_maximum_is_rejected(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.catalog_authority import CatalogAuthorityError, catalog_approval_payload
        from guardian_core.policy import EXPECTED_POLICY_SHA256

        profile = sample_profile()
        catalog = attest_catalog(
            sample_catalog(),
            profile,
            sequence=1 << 63,
            issued_at=NOW,
        )

        with self.assertRaisesRegex(CatalogAuthorityError, "at most"):
            catalog_approval_payload(
                policy_digest=EXPECTED_POLICY_SHA256,
                profile_digest=sha256_digest(profile),
                catalog=catalog,
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.flutter_runner import FlutterRunnerUnsupportedError, _select_analyzer
from tests.flutter_authority_test_support import create_test_dart_sdk


class FlutterDartOnlyRunnerTests(unittest.TestCase):
    def test_flutter_without_dart_is_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "product"
            product.mkdir()
            flutter = root / "flutter.exe"
            flutter.write_bytes(b"untrusted-for-this-contract")

            with mock.patch(
                "guardian_core.flutter_runner.shutil.which",
                side_effect=lambda name: str(flutter) if name == "flutter" else None,
            ):
                with self.assertRaises(FlutterRunnerUnsupportedError):
                    _select_analyzer(product, {"not": "used"})

    def test_dart_is_selected_even_when_flutter_is_discoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "product"
            product.mkdir()
            dart, binding = create_test_dart_sdk(root / "dart-sdk")
            dart_alias = dart.parent / ".." / dart.parent.name / dart.name
            flutter = root / "flutter.exe"
            flutter.write_bytes(b"not-selected")

            def which(name: str) -> str | None:
                return {"dart": str(dart_alias), "flutter": str(flutter)}.get(name)

            with mock.patch(
                "guardian_core.flutter_runner.shutil.which", side_effect=which
            ):
                executable, evidence = _select_analyzer(product, binding)

            self.assertEqual(executable, dart.resolve())
            self.assertEqual(
                evidence["contentDigest"], binding["dartSdk"]["contentDigest"]
            )


if __name__ == "__main__":
    unittest.main()

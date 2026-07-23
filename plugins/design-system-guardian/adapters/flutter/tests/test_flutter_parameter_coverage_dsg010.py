from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FlutterParameterCoverageTests(unittest.TestCase):
    def test_common_visual_dimension_parameters_are_governed(self) -> None:
        source = (ROOT / "lib/src/rules/rule_support.dart").read_text(
            encoding="utf-8"
        )
        for parameter in (
            "blurRadius",
            "dimension",
            "elevation",
            "endIndent",
            "indent",
            "itemExtent",
            "margin",
            "spreadRadius",
            "thickness",
        ):
            with self.subTest(parameter=parameter):
                self.assertIn(f"'{parameter}'", source)


if __name__ == "__main__":
    unittest.main()

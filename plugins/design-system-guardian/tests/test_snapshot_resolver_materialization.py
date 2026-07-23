

import tempfile
import unittest
from pathlib import Path

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class SnapshotResolverMaterializationTest(unittest.TestCase):
    def test_snapshot_tokens_are_the_selected_resolver_context_not_unmodified_base(self) -> None:
        catalog = sample_catalog()
        light = {"colorSpace": "srgb", "components": [1, 1, 1], "alpha": 1}
        dark = {"colorSpace": "srgb", "components": [0, 0, 0], "alpha": 1}
        catalog["tokens"]["color"]["action"]["primary"]["$value"] = light
        catalog["resolver"] = {
            "version": "2025.10",
            "modifiers": {
                "theme": {
                    "contexts": {
                        "light": [],
                        "dark": [
                            {
                                "color": {
                                    "action": {
                                        "primary": {"$type": "color", "$value": dark}
                                    }
                                }
                            }
                        ],
                    },
                    "default": "light",
                }
            },
            "resolutionOrder": [{"$ref": "#/modifiers/theme"}],
        }
        catalog["resolverContext"] = {"theme": "dark"}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            snapshot = ingest_test_snapshot(home, sample_profile(), catalog, now=NOW)
        self.assertEqual(snapshot["tokens"]["color.action.primary"]["value"], dark)
        self.assertEqual(snapshot["resolver"]["evidence"]["contexts"], {"theme": "dark"})

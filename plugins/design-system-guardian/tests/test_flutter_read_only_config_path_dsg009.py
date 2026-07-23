import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class FlutterReadOnlyConfigPathTest(unittest.TestCase):
    def test_adapter_supports_exact_external_config_without_product_edit(self) -> None:
        source = (
            PLUGIN_ROOT
            / "adapters"
            / "flutter"
            / "lib"
            / "src"
            / "config"
            / "adapter_config.dart"
        ).read_text(encoding="utf-8")
        self.assertIn("DESIGN_SYSTEM_GUARDIAN_FLUTTER_CONFIG", source)
        self.assertIn("Platform.environment[_adapterConfigEnvironment]", source)
        self.assertIn("environmentPath.trim() != environmentPath", source)
        self.assertIn("cannot access adapter config", source)
        self.assertIn("configDigest does not match canonical config content", source)


if __name__ == "__main__":
    unittest.main()

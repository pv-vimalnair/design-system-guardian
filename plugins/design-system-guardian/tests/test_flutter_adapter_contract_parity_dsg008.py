import copy
import importlib.util
import unittest
from pathlib import Path

from tests.test_audit_dsg003 import sample_pin
from tests.test_flutter_adapter_normalization_dsg003 import (
    clean_flutter_result,
    diagnostic,
    flutter_config,
)


def load_shipped_contract_tool():
    tool_path = (
        Path(__file__).resolve().parents[1]
        / "adapters"
        / "flutter"
        / "tools"
        / "guardian_flutter_contract.py"
    )
    spec = importlib.util.spec_from_file_location("guardian_flutter_contract_parity", tool_path)
    if spec is None or spec.loader is None:
        raise AssertionError("Flutter contract tool could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FlutterContractParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_shipped_contract_tool()

    def assert_parity(self, raw: dict) -> None:
        from guardian_core.flutter_adapter import normalize_flutter_adapter_result

        pin = sample_pin()
        config = flutter_config(pin)
        core = normalize_flutter_adapter_result(raw, adapter_config=config, run_pin=pin)
        shipped = self.tool.normalize_flutter_result_to_core(raw, config, pin)
        self.assertEqual(core, shipped)

    def test_clean_result_matches_shipped_contract_tool(self) -> None:
        self.assert_parity(clean_flutter_result(sample_pin()))

    def test_violation_result_matches_shipped_contract_tool(self) -> None:
        raw = copy.deepcopy(clean_flutter_result(sample_pin()))
        raw["diagnostics"] = [diagnostic("guardian_unapproved_color")]
        raw["coverage"]["colors"]["diagnosticCount"] = 1
        raw["productionReady"] = False
        self.assert_parity(raw)

    def test_visual_primitive_violation_matches_shipped_contract_tool(self) -> None:
        raw = copy.deepcopy(clean_flutter_result(sample_pin()))
        raw["diagnostics"] = [diagnostic("guardian_unapproved_visual_primitive")]
        raw["coverage"]["components"]["diagnosticCount"] = 1
        raw["productionReady"] = False
        self.assert_parity(raw)


if __name__ == "__main__":
    unittest.main()

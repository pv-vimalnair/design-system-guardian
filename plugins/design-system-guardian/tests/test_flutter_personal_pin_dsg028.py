from __future__ import annotations

import copy
import unittest

from tests.test_figma_personal_selection_dsg028 import personal_context
from tests.test_flutter_adapter_contract_parity_dsg008 import load_shipped_contract_tool
from tests.test_flutter_adapter_normalization_dsg003 import (
    clean_flutter_result,
    flutter_config,
)


class PersonalFlutterPinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_shipped_contract_tool()

    def test_personal_v2_pin_has_core_shipped_and_runner_parity(self) -> None:
        from guardian_core.flutter_adapter import normalize_flutter_adapter_result
        from guardian_core.flutter_runner import _validate_run_pin

        pin, _ = personal_context()
        config = flutter_config(pin)
        raw = clean_flutter_result(pin)

        core = normalize_flutter_adapter_result(
            raw,
            adapter_config=config,
            run_pin=pin,
        )
        shipped = self.tool.normalize_flutter_result_to_core(raw, config, pin)
        runner = _validate_run_pin(pin, config)

        self.assertEqual(core, shipped)
        self.assertEqual(runner, pin)
        self.assertEqual(core["adapter"], "flutter")
        self.assertTrue(core["supported"])

    def test_clean_personal_flutter_coverage_never_claims_allowed(self) -> None:
        from guardian_core.audit import adapter_audit_projection
        from guardian_core.flutter_adapter import normalize_flutter_adapter_result

        pin, _ = personal_context()
        normalized = normalize_flutter_adapter_result(
            clean_flutter_result(pin),
            adapter_config=flutter_config(pin),
            run_pin=pin,
        )
        self.assertTrue(
            all(
                category["status"] == "allowed"
                for category in normalized["categories"].values()
            )
        )

        coverage, diagnostics = adapter_audit_projection(
            normalized,
            pin["sourceCut"],
            run_pin=pin,
        )

        self.assertEqual(diagnostics, [])
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["status"], "not_assessed")
        self.assertTrue(
            all(
                category["status"] == "not_assessed"
                for category in coverage["categories"].values()
            )
        )

    def test_malformed_personal_v2_pin_fails_at_every_flutter_boundary(self) -> None:
        from guardian_core.flutter_adapter import (
            FlutterAdapterIntegrityError,
            normalize_flutter_adapter_result,
        )
        from guardian_core.flutter_runner import (
            FlutterRunnerIntegrityError,
            _validate_run_pin,
        )

        pin, _ = personal_context()
        cases: list[dict] = []
        wrong_authority = copy.deepcopy(pin)
        wrong_authority["authorityMode"] = "enterprise"
        cases.append(wrong_authority)
        empty_selected = copy.deepcopy(pin)
        empty_selected["selectedLibraryFileKeys"] = []
        cases.append(empty_selected)
        unpublished_selected = copy.deepcopy(pin)
        unpublished_selected["libraryDecisions"][0]["published"] = False
        cases.append(unpublished_selected)

        for changed in cases:
            config = flutter_config(changed)
            raw = clean_flutter_result(changed)
            with self.subTest(changed=changed):
                with self.assertRaises(FlutterAdapterIntegrityError):
                    normalize_flutter_adapter_result(
                        raw,
                        adapter_config=config,
                        run_pin=changed,
                    )
                with self.assertRaises(self.tool.ContractError):
                    self.tool.normalize_flutter_result_to_core(raw, config, changed)
                with self.assertRaises(FlutterRunnerIntegrityError):
                    _validate_run_pin(changed, config)


if __name__ == "__main__":
    unittest.main()

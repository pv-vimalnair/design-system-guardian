import copy
import unittest

from tests.test_audit_dsg003 import allowed_ux_check, sample_pin
from tests.test_audit_dsg003 import sample_project_evidence, sample_snapshot


CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)
IDENTITY_CATEGORIES = (
    "colors",
    "textStyles",
    "icons",
    "dimensions",
    "effects",
    "motion",
    "widgets",
)


def flutter_config(pin: dict) -> dict:
    from guardian_core.canonical import sha256_digest
    from guardian_core.flutter_toolchain import current_platform_id, expected_dart_executable

    platform_id = current_platform_id()
    unsigned = {
        "schemaVersion": 1,
        "adapter": "flutter",
        "adapterVersion": "0.1.0",
        "profileId": pin["profileId"],
        "policyDigest": pin["policyDigest"],
        "snapshotId": pin["snapshotId"],
        "sourceCutDigest": sha256_digest(pin["sourceCut"]),
        "toolchain": {
            "platformId": platform_id,
            "dartSdk": {
                "contentDigest": "d" * 64,
                "executableRelativePath": expected_dart_executable(platform_id),
            },
        },
        "requiredPackages": {
            "flutter": {
                "contentDigest": "f" * 64,
                "repositoryCommit": "c" * 40,
            }
        },
        "approvedPackages": {},
        "approvedIdentities": {category: [] for category in IDENTITY_CATEGORIES},
        "componentVariants": {},
    }
    return {**unsigned, "configDigest": sha256_digest(unsigned)}


def clean_flutter_result(pin: dict, *, assessed_files: int = 3, total_files: int = 3) -> dict:
    from guardian_core.canonical import sha256_digest

    config = flutter_config(pin)
    complete = assessed_files == total_files and total_files > 0
    status = "allowed" if complete else "not_assessed"
    lane_status = "allowed" if complete else "not_assessed"
    return {
        "schemaVersion": 1,
        "adapter": "flutter",
        "adapterVersion": "0.1.0",
        "status": status,
        "binding": {
            "profileId": pin["profileId"],
            "policyDigest": pin["policyDigest"],
            "snapshotId": pin["snapshotId"],
            "sourceCutDigest": sha256_digest(pin["sourceCut"]),
            "configDigest": config["configDigest"],
        },
        "analysis": {
            "method": "dart_analyzer_ast",
            "complete": complete,
            "assessedFiles": assessed_files,
            "totalFiles": total_files,
        },
        "diagnostics": [],
        "coverage": {
            category: {
                "status": lane_status,
                "method": "dart_analyzer_ast",
                "diagnosticCount": 0,
            }
            for category in CATEGORIES
        },
        "suppressionScan": {
            "schemaVersion": 1,
            "method": "conservative_text_scan",
            "astProof": False,
            "findings": [],
        },
        "productionReady": complete,
    }


def diagnostic(code: str, *, line: int = 12) -> dict:
    return {
        "severity": "WARNING",
        "code": code,
        "path": "lib/screen.dart",
        "line": line,
        "column": 8,
        "length": 10,
        "message": f"Guardian diagnostic {code}.",
    }


class FlutterAdapterNormalizationTest(unittest.TestCase):
    def normalize(self, raw: dict):
        from guardian_core.flutter_adapter import normalize_flutter_adapter_result

        pin = sample_pin()
        return normalize_flutter_adapter_result(
            raw,
            adapter_config=flutter_config(pin),
            run_pin=pin,
        )

    def evaluate(self, raw: dict):
        from guardian_core.audit import evaluate_audit

        pin = sample_pin()
        normalized = self.normalize(raw)
        return evaluate_audit(
            run_pin=pin,
            adapter_result=normalized,
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

    def test_clean_bound_flutter_result_normalizes_real_file_counts(self) -> None:
        from guardian_core.contracts import ExitCode

        result = self.evaluate(clean_flutter_result(sample_pin()))
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertTrue(result.result["coverage"]["complete"])
        self.assertEqual(result.result["coverage"]["assessedFiles"], 3)
        self.assertEqual(result.result["coverage"]["totalFiles"], 3)

    def test_exact_color_diagnostic_is_a_violation_not_invalid_evidence(self) -> None:
        from guardian_core.contracts import ExitCode

        raw = clean_flutter_result(sample_pin())
        raw["productionReady"] = False
        raw["coverage"]["colors"]["diagnosticCount"] = 1
        raw["diagnostics"] = [diagnostic("guardian_unapproved_color")]
        result = self.evaluate(raw)
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertEqual(result.result["designSystemLane"]["status"], "conflict")
        self.assertEqual(result.result["designSystemLane"]["violations"][0]["category"], "colors")

    def test_spacing_and_radius_diagnostics_remain_distinct(self) -> None:
        from guardian_core.contracts import ExitCode

        raw = clean_flutter_result(sample_pin())
        raw["productionReady"] = False
        raw["coverage"]["spacing"]["diagnosticCount"] = 1
        raw["coverage"]["radii"]["diagnosticCount"] = 1
        raw["diagnostics"] = [
            diagnostic("guardian_unapproved_dimension", line=20),
            diagnostic("guardian_unapproved_radius", line=21),
        ]
        result = self.evaluate(raw)
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertEqual(
            {item["category"] for item in result.result["designSystemLane"]["violations"]},
            {"spacing", "radii"},
        )

    def test_incomplete_zero_file_and_unsupported_coverage_never_pass(self) -> None:
        from guardian_core.contracts import ExitCode

        incomplete = clean_flutter_result(sample_pin(), assessed_files=2, total_files=3)
        result = self.evaluate(incomplete)
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertFalse(result.result["coverage"]["complete"])

        zero = clean_flutter_result(sample_pin(), assessed_files=0, total_files=0)
        with self.assertRaisesRegex(Exception, "at least one"):
            self.normalize(zero)

        unsupported = clean_flutter_result(sample_pin())
        unsupported["status"] = "unsupported"
        unsupported["productionReady"] = False
        unsupported["coverage"]["motion"]["status"] = "unsupported"
        result = self.evaluate(unsupported)
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)

    def test_config_binding_drift_unknown_codes_order_and_invalid_claims_fail_integrity(self) -> None:
        from guardian_core.flutter_adapter import FlutterAdapterIntegrityError, normalize_flutter_adapter_result

        pin = sample_pin()
        config = flutter_config(pin)
        cases = []

        profile = clean_flutter_result(pin)
        profile["binding"]["profileId"] = "other-company"
        cases.append(("profile", profile, config))

        altered_config = copy.deepcopy(config)
        altered_config["approvedIdentities"]["colors"].append(
            "package:design_system/design_system.dart#Colors.primary"
        )
        cases.append(("config-digest", clean_flutter_result(pin), altered_config))

        unknown = clean_flutter_result(pin)
        unknown["productionReady"] = False
        unknown["coverage"]["colors"]["diagnosticCount"] = 1
        unknown["diagnostics"] = [diagnostic("guardian_closest_color")]
        cases.append(("unknown-code", unknown, config))

        unordered = clean_flutter_result(pin)
        unordered["productionReady"] = False
        unordered["coverage"]["colors"]["diagnosticCount"] = 2
        unordered["diagnostics"] = [
            diagnostic("guardian_unapproved_color", line=20),
            diagnostic("guardian_unapproved_color", line=10),
        ]
        cases.append(("order", unordered, config))

        invalid = clean_flutter_result(pin)
        invalid["status"] = "invalid"
        invalid["productionReady"] = False
        cases.append(("invalid", invalid, config))

        for label, raw, supplied_config in cases:
            with self.subTest(label=label), self.assertRaises(FlutterAdapterIntegrityError):
                normalize_flutter_adapter_result(
                    raw,
                    adapter_config=supplied_config,
                    run_pin=pin,
                )

    def test_suppression_is_a_violation_across_all_categories(self) -> None:
        from guardian_core.contracts import ExitCode

        raw = clean_flutter_result(sample_pin())
        raw["productionReady"] = False
        raw["suppressionScan"]["findings"] = [
            {
                "path": "lib/screen.dart",
                "line": 2,
                "text": "// guardian-ignore",
                "kind": "guardian_bypass_marker",
            }
        ]
        result = self.evaluate(raw)
        self.assertEqual(result.exit_code, ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
        self.assertEqual(
            {item["category"] for item in result.result["designSystemLane"]["violations"]},
            set(CATEGORIES),
        )


if __name__ == "__main__":
    unittest.main()

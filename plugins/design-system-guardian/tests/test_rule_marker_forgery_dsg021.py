from __future__ import annotations

import unittest


class RuleMarkerForgeryTest(unittest.TestCase):
    def test_artifact_cannot_forge_internal_parser_warnings_or_success(self) -> None:
        from guardian_core.rules import validate_rules

        forged = {
            "parseWarning": {
                "ruleId": None,
                "ruleClass": None,
                "reasonCode": "ok",
            }
        }
        result = validate_rules(
            [forged], known_identities=frozenset(), source_type="artifact"
        )
        self.assertEqual(result["report"]["status"], "invalid")
        self.assertEqual(result["report"]["summary"]["errors"], 1)
        self.assertEqual(result["report"]["entries"][0]["reasonCode"], "unknown_field")
        self.assertEqual(result["rules"], [])

    def test_unknown_internal_reason_is_normalized_to_safe_vocabulary(self) -> None:
        from guardian_core.rules import validate_rules

        result = validate_rules(
            [{"parseError": {"reasonCode": "private arbitrary detail"}}],
            known_identities=frozenset(),
            source_type="figma_description",
        )
        self.assertEqual(result["report"]["status"], "invalid")
        self.assertEqual(result["report"]["entries"][0]["reasonCode"], "invalid_value")
        self.assertNotIn("private arbitrary detail", str(result["report"]))


if __name__ == "__main__":
    unittest.main()

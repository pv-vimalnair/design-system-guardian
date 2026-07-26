from __future__ import annotations

import unittest


class RuleCodeFenceTest(unittest.TestCase):
    def test_code_fenced_marker_example_never_becomes_a_rule(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        description = (
            "```text\n"
            "[dsg-rule id=example.rule class=informative]\n"
            "This is only documentation.\n"
            "[/dsg-rule]\n"
            "```"
        )
        result = validate_rules(
            parse_description_markers(
                description,
                host_kind="system",
                host_identity="Synthetic/System",
                figma={"fileKey": "F1", "nodeId": "1:2", "sourceVersion": "v9"},
            ),
            known_identities=frozenset(),
            source_type="figma_description",
        )
        self.assertEqual(result["rules"], [])
        self.assertEqual(result["report"]["status"], "invalid")
        self.assertIn(
            "no_rule_markers",
            {entry["reasonCode"] for entry in result["report"]["entries"]},
        )


if __name__ == "__main__":
    unittest.main()

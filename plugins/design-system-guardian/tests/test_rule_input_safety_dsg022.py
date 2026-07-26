from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class RuleInputSafetyTest(unittest.TestCase):
    def test_nonstandard_json_number_fails_as_safe_invalid_json(self) -> None:
        from guardian_core.rules import RuleValidationError, load_rule_artifact

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text('[{"schemaVersion":NaN}]', encoding="utf-8")
            with self.assertRaises(RuleValidationError) as caught:
                load_rule_artifact(path)
            self.assertEqual(caught.exception.reason_code, "invalid_json")
            self.assertNotIn(str(path), str(caught.exception))


if __name__ == "__main__":
    unittest.main()

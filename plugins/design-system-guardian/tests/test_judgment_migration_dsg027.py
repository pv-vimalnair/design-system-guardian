from __future__ import annotations
import tempfile, unittest
from pathlib import Path

class JudgmentMigrationTest(unittest.TestCase):
    def test_absent_legacy_state_stays_absent_and_future_head_refuses(self):
        from guardian_core.canonical import atomic_write_json
        from guardian_core.judgment_decisions import JudgmentDecisionIntegrityError, read_judgment_status
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            status = read_judgment_status(home, profile_id="example-company", run_id="legacy-run")
            self.assertEqual(status["status"], "not_assessed")
            self.assertFalse((home / "profiles").exists())
            path = home / "profiles" / "example-company" / "audits" / "legacy-run" / "current-judgment-history.json"
            atomic_write_json(path, {"schemaVersion": 2})
            with self.assertRaises(JudgmentDecisionIntegrityError):
                read_judgment_status(home, profile_id="example-company", run_id="legacy-run")

if __name__ == "__main__": unittest.main()
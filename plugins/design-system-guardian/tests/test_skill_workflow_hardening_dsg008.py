import unittest

from tests.test_skill_contracts import skill_text


class SkillWorkflowHardeningTest(unittest.TestCase):
    def test_build_requires_host_owned_audit_and_sealed_source_recheck(self) -> None:
        text = skill_text("build-with-design-system").lower()
        self.assertIn("guardian adapter flutter config", text)
        self.assertIn("never hand-author, broaden, merge, or infer", text)
        self.assertIn("do not supply an analyzer result", text)
        self.assertIn("host-owned runner", text)
        self.assertIn("only `schemaversion`, the exact `projectroot`", text)
        self.assertIn("finalization rechecks the sealed source evidence", text)
        self.assertIn("private pilot cannot exit 0", text)

    def test_audit_host_runner_does_not_mutate_product_tree(self) -> None:
        text = skill_text("audit-design-system").lower()
        self.assertIn("this skill is read-only for the product and source tree", text)
        self.assertIn("exact `projectroot`", text)
        self.assertIn("never include or hand-author an adapter result", text)
        self.assertIn("external staged copy of every relevant dart file", text)
        self.assertIn("seals source-bound analysis evidence", text)
        self.assertIn("reopens the sealed analysis attestation", text)
        self.assertIn("canonicalizes this lane to `not_assessed`, exit `4`", text)


if __name__ == "__main__":
    unittest.main()

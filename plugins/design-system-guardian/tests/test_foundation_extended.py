import unittest


EXPECTED_STATUSES = {
    "allowed",
    "missing",
    "ambiguous",
    "conflict",
    "invalid",
    "unsupported",
    "stale",
    "source_unavailable",
    "source_incomplete",
    "not_assessed",
}


class ExtendedFoundationContractTest(unittest.TestCase):
    def test_exact_resolution_statuses(self) -> None:
        from guardian_core.contracts import ResolutionStatus

        self.assertEqual({member.value for member in ResolutionStatus}, EXPECTED_STATUSES)

    def test_canonical_json_and_digest_are_deterministic(self) -> None:
        from guardian_core.canonical import canonical_json_bytes, sha256_digest

        first = {"z": [3, 2, 1], "a": {"unicode": "Example Company ₦", "ok": True}}
        second = {"a": {"ok": True, "unicode": "Example Company ₦"}, "z": [3, 2, 1]}
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(sha256_digest(first), sha256_digest(second))
        self.assertRegex(sha256_digest(first), r"^[0-9a-f]{64}$")

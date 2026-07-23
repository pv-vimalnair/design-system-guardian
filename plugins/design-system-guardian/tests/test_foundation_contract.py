import unittest


class FoundationContractTest(unittest.TestCase):
    def test_exact_exit_codes(self) -> None:
        from guardian_core.contracts import ExitCode

        self.assertEqual(
            {member.name: member.value for member in ExitCode},
            {
                "PASS": 0,
                "VIOLATION_OR_SENTINEL": 1,
                "INVALID_POLICY_CONFIG_OR_INTEGRITY": 2,
                "SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE": 3,
                "UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE": 4,
            },
        )


if __name__ == "__main__":
    unittest.main()

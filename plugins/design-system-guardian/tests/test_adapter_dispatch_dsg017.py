from __future__ import annotations

import copy
import unittest

from tests.test_profile_snapshot import sample_profile


class AdapterDispatchTest(unittest.TestCase):
    def test_figma_is_plug_and_play_from_the_existing_profile_allowlist(self) -> None:
        from guardian_core.adapter_dispatch import select_adapter

        profile = sample_profile()
        self.assertNotIn("figma", profile["adapters"])
        self.assertEqual(select_adapter(profile, "figma"), "figma")

    def test_unknown_disabled_and_malformed_adapters_fail_closed(self) -> None:
        from guardian_core.adapter_dispatch import AdapterDispatchError, select_adapter

        profile = sample_profile()
        with self.assertRaises(AdapterDispatchError):
            select_adapter(profile, "web")

        disabled = copy.deepcopy(profile)
        disabled["adapters"]["figma"] = {"enabled": False}
        with self.assertRaises(AdapterDispatchError):
            select_adapter(disabled, "figma")

        malformed = copy.deepcopy(profile)
        malformed["figma"]["allowlistedLibraryFiles"] = []
        with self.assertRaises(AdapterDispatchError):
            select_adapter(malformed, "figma")


if __name__ == "__main__":
    unittest.main()

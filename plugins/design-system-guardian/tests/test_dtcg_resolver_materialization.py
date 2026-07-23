import unittest


def color(red: float, green: float, blue: float) -> dict:
    return {"colorSpace": "srgb", "components": [red, green, blue], "alpha": 1}


class ResolverMaterializationTest(unittest.TestCase):
    def test_resolution_order_materializes_selected_context_without_guessing(self) -> None:
        from guardian_core.dtcg_resolver import materialize_resolver_tokens

        base = {
            "color": {
                "$type": "color",
                "surface": {"$value": color(1, 1, 1)},
            }
        }
        resolver = {
            "version": "2025.10",
            "sets": {"foundation": {"sources": [base]}},
            "modifiers": {
                "theme": {
                    "contexts": {
                        "light": [],
                        "dark": [
                            {"color": {"surface": {"$type": "color", "$value": color(0, 0, 0)}}}
                        ],
                    },
                    "default": "light",
                }
            },
            "resolutionOrder": [
                {"$ref": "#/sets/foundation"},
                {"$ref": "#/modifiers/theme"},
            ],
        }
        light = materialize_resolver_tokens({}, resolver, {"theme": "light"})
        dark = materialize_resolver_tokens({}, resolver, {"theme": "dark"})
        self.assertEqual(light["tokens"]["color.surface"]["value"], color(1, 1, 1))
        self.assertEqual(dark["tokens"]["color.surface"]["value"], color(0, 0, 0))
        self.assertEqual(dark["evidence"]["contexts"], {"theme": "dark"})

    def test_external_unmaterialized_source_is_an_error(self) -> None:
        from guardian_core.dtcg import DtcgValidationError
        from guardian_core.dtcg_resolver import materialize_resolver_tokens

        resolver = {
            "version": "2025.10",
            "sets": {"external": {"sources": [{"$ref": "tokens/base.json"}]}},
            "resolutionOrder": [{"$ref": "#/sets/external"}],
        }
        with self.assertRaisesRegex(DtcgValidationError, "external"):
            materialize_resolver_tokens({}, resolver, {})

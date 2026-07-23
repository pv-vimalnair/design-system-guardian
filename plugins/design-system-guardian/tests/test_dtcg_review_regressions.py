import unittest


def color(red: float, green: float, blue: float) -> dict:
    return {"colorSpace": "srgb", "components": [red, green, blue]}


class DtcgReviewRegressionTest(unittest.TestCase):
    def test_top_level_ref_may_target_a_property_value(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        tokens = resolve_token_document(
            {
                "spacing": {
                    "$type": "dimension",
                    "$value": {"value": 16, "unit": "px"},
                },
                "spacing-number": {
                    "$type": "number",
                    "$ref": "#/spacing/$value/value",
                },
            }
        )

        self.assertEqual(tokens["spacing-number"]["value"], 16)
        self.assertIsNone(tokens["spacing-number"]["alias"])

    def test_property_pointer_preserves_source_composite_semantic_type(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        document = {
            "base": {
                "$type": "typography",
                "$value": {
                    "fontFamily": "Inter",
                    "fontSize": {"value": 16, "unit": "px"},
                    "fontWeight": 400,
                    "letterSpacing": {"value": 0, "unit": "px"},
                    "lineHeight": 1.5,
                },
            },
            "invalid": {
                "$type": "typography",
                "$value": {
                    "fontFamily": "Inter",
                    "fontSize": {"value": 16, "unit": "px"},
                    "fontWeight": 400,
                    "letterSpacing": {"value": 0, "unit": "px"},
                    "lineHeight": {"$ref": "#/base/$value/fontWeight"},
                },
            },
        }

        with self.assertRaisesRegex(DtcgValidationError, "type mismatch"):
            resolve_token_document(document)

    def test_resolver_set_cycles_are_canonical_validation_errors(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        resolver = {
            "version": "2025.10",
            "sets": {
                "a": {"sources": [{"$ref": "#/sets/b"}]},
                "b": {"sources": [{"$ref": "#/sets/a"}]},
            },
            "resolutionOrder": [{"$ref": "#/sets/a"}],
        }

        with self.assertRaisesRegex(DtcgValidationError, "Circular resolver set reference"):
            validate_resolver_document(resolver, {})

    def test_gradient_positions_are_clamped_as_specified(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        tokens = resolve_token_document(
            {
                "clamped": {
                    "$type": "gradient",
                    "$value": [
                        {"color": color(1, 1, 0), "position": -99},
                        {"color": color(1, 0, 0), "position": 42},
                    ],
                }
            }
        )

        self.assertEqual(
            [stop["position"] for stop in tokens["clamped"]["value"]],
            [0, 1],
        )

    def test_official_gradient_reference_arrays_remain_single_nested_values(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        white = {"color": color(1, 1, 1), "position": 0}
        black = {"color": color(0, 0, 0), "position": 1}
        document = {
            "brand": {
                "secondary": {"$type": "color", "$value": color(0, 1, 0.4)},
            },
            "gradient": {
                "start-stop": {"$type": "gradient", "$value": [white]},
                "end-stop": {"$type": "gradient", "$value": [black]},
            },
            "gradient-with-references": {
                "$type": "gradient",
                "$value": [
                    "{gradient.start-stop}",
                    {"color": "{brand.secondary}", "position": 0.333},
                    "{gradient.end-stop}",
                ],
            },
        }

        tokens = resolve_token_document(document)
        value = tokens["gradient-with-references"]["value"]

        self.assertEqual(len(value), 3)
        self.assertEqual(value[0], [white])
        self.assertEqual(value[2], [black])
        self.assertEqual(value[1]["color"], color(0, 1, 0.4))

    def test_resolver_conflict_replaces_the_complete_token_declaration(self) -> None:
        from guardian_core.dtcg_resolver import materialize_resolver_tokens

        resolver = {
            "version": "2025.10",
            "sets": {
                "foundation": {
                    "sources": [
                        {
                            "base": {"$type": "number", "$value": 2},
                            "semantic": {
                                "$type": "number",
                                "$value": 1,
                                "$deprecated": "stale",
                                "$description": "stale",
                                "$extensions": {"stale": True},
                            },
                        },
                        {"semantic": {"$type": "number", "$value": 2}},
                    ]
                }
            },
            "resolutionOrder": [{"$ref": "#/sets/foundation"}],
        }

        token = materialize_resolver_tokens({}, resolver, {})["tokens"]["semantic"]

        self.assertEqual(token["value"], 2)
        self.assertIsNone(token["alias"])
        self.assertFalse(token["deprecated"])
        self.assertIsNone(token["description"])
        self.assertEqual(token["extensions"], {})


if __name__ == "__main__":
    unittest.main()

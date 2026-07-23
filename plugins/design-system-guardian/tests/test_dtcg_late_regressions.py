import unittest


def dimension(value: float, unit: str = "px") -> dict:
    return {"value": value, "unit": unit}


def color(red: float, green: float, blue: float) -> dict:
    return {"colorSpace": "srgb", "components": [red, green, blue]}


def shadow(offset: float) -> dict:
    return {
        "color": color(0, 0, 0),
        "offsetX": dimension(offset),
        "offsetY": dimension(offset),
        "blur": dimension(offset + 1),
        "spread": dimension(0),
    }


class DtcgLateRegressionTest(unittest.TestCase):
    def test_whole_token_reference_cannot_fill_an_atomic_composite_field(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        document = {
            "looks-compatible": {"$type": "fontFamily", "$value": "px"},
            "spacing": {
                "$type": "dimension",
                "$value": {"value": 8, "unit": "{looks-compatible}"},
            },
        }

        with self.assertRaisesRegex(DtcgValidationError, "type mismatch"):
            resolve_token_document(document)

    def test_defs_reference_cycle_is_a_canonical_validation_error(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        resolver = {
            "version": "2025.10",
            "$defs": {
                "a": {"$ref": "#/$defs/b"},
                "b": {"$ref": "#/$defs/a"},
            },
            "sets": {
                "cyclic": {"sources": [{"$ref": "#/$defs/a"}]},
            },
            "resolutionOrder": [{"$ref": "#/sets/cyclic"}],
        }

        with self.assertRaisesRegex(DtcgValidationError, "Circular resolver source reference"):
            validate_resolver_document(resolver, {})

    def test_referenced_shadow_array_is_preserved_as_one_nested_value(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        source_value = [shadow(1), shadow(3)]
        tokens = resolve_token_document(
            {
                "source": {"$type": "shadow", "$value": source_value},
                "composed": {
                    "$type": "shadow",
                    "$value": ["{source}"],
                },
            }
        )

        self.assertEqual(tokens["composed"]["value"], [source_value])

    def test_group_extends_replaces_the_complete_token_including_metadata(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        tokens = resolve_token_document(
            {
                "base": {
                    "$type": "number",
                    "level": {
                        "$value": 1,
                        "$description": "base description",
                        "$deprecated": "base deprecation",
                        "$extensions": {"com.example": {"base": True}},
                    },
                },
                "override": {
                    "$extends": "{base}",
                    "level": {"$value": 2},
                },
            }
        )

        token = tokens["override.level"]
        self.assertEqual(token["value"], 2)
        self.assertIsNone(token["description"])
        self.assertFalse(token["deprecated"])
        self.assertEqual(token["extensions"], {})

    def test_normative_group_ref_is_resolved_as_a_group_extension(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        tokens = resolve_token_document(
            {
                "base": {
                    "$type": "dimension",
                    "small": {"$value": dimension(4)},
                    "medium": {"$value": dimension(8)},
                },
                "large": {
                    "$ref": "#/base",
                    "small": {"$value": dimension(12)},
                },
            }
        )

        self.assertNotIn("large", tokens)
        self.assertEqual(tokens["large.small"]["value"], dimension(12))
        self.assertEqual(tokens["large.medium"]["value"], dimension(8))



    def test_official_2025_10_schema_is_supported_only_at_document_root(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        schema = "https://www.designtokens.org/schemas/2025.10/format.json"
        resolved = resolve_token_document(
            {
                "$schema": schema,
                "spacing": {"$type": "dimension", "$value": dimension(8)},
            }
        )
        self.assertEqual(resolved["spacing"]["value"], dimension(8))

        for invalid_schema in ("", "https://example.com/format.json", 202510, None):
            with self.subTest(invalid_schema=invalid_schema):
                with self.assertRaisesRegex(DtcgValidationError, r"\$schema"):
                    resolve_token_document(
                        {
                            "$schema": invalid_schema,
                            "spacing": {"$type": "dimension", "$value": dimension(8)},
                        }
                    )

        with self.assertRaisesRegex(DtcgValidationError, "Unknown reserved property"):
            resolve_token_document(
                {
                    "nested": {
                        "$schema": schema,
                        "spacing": {"$type": "dimension", "$value": dimension(8)},
                    }
                }
            )

    def test_atomic_property_pointers_cannot_impersonate_font_family(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        sources = {
            "brand": {
                "$type": "color",
                "$value": {
                    "colorSpace": "srgb",
                    "components": [0.1, 0.2, 0.3],
                    "hex": "#1A334D",
                },
            },
            "space": {
                "$type": "dimension",
                "$value": {"value": 8, "unit": "px"},
            },
        }
        for pointer in (
            "#/brand/$value/hex",
            "#/brand/$value/colorSpace",
            "#/space/$value/unit",
        ):
            with self.subTest(pointer=pointer):
                document = {
                    **sources,
                    "impostor": {
                        "$type": "fontFamily",
                        "$value": {"$ref": pointer},
                    },
                }
                with self.assertRaisesRegex(DtcgValidationError, "type mismatch"):
                    resolve_token_document(document)

if __name__ == "__main__":
    unittest.main()

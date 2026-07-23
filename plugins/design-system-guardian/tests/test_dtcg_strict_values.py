import unittest


def color(
    red: float = 0.1,
    green: float = 0.2,
    blue: float = 0.3,
    *,
    alpha: float = 1,
) -> dict:
    return {
        "colorSpace": "srgb",
        "components": [red, green, blue],
        "alpha": alpha,
    }


def dimension(value: float = 1, unit: str = "px") -> dict:
    return {"value": value, "unit": unit}


class DtcgStrictValueTest(unittest.TestCase):
    def test_property_references_materialize_nested_objects_and_array_indices(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        document = {
            "palette": {"$type": "color", "$value": color(0.2, 0.4, 0.6, alpha=0.5)},
            "space": {"$type": "dimension", "$value": dimension(8)},
            "curve": {"$type": "cubicBezier", "$value": [0.1, 0.2, 0.3, 0.4]},
            "picked": {
                "$type": "number",
                "$value": {"$ref": "#/curve/$value/2"},
            },
            "shadow": {
                "$type": "shadow",
                "$value": {
                    "color": {
                        "colorSpace": {"$ref": "#/palette/$value/colorSpace"},
                        "components": [
                            {"$ref": "#/palette/$value/components/2"},
                            {"$ref": "#/palette/$value/components/1"},
                            {"$ref": "#/palette/$value/components/0"},
                        ],
                        "alpha": {"$ref": "#/palette/$value/alpha"},
                    },
                    "offsetX": {
                        "value": {"$ref": "#/space/$value/value"},
                        "unit": {"$ref": "#/space/$value/unit"},
                    },
                    "offsetY": "{space}",
                    "blur": dimension(2),
                    "spread": dimension(0),
                },
            },
        }

        tokens = resolve_token_document(document)

        self.assertEqual(tokens["picked"]["value"], 0.3)
        self.assertEqual(
            tokens["shadow"]["value"]["color"],
            color(0.6, 0.4, 0.2, alpha=0.5),
        )
        self.assertEqual(tokens["shadow"]["value"]["offsetX"], dimension(8))
        self.assertEqual(tokens["shadow"]["value"]["offsetY"], dimension(8))

    def test_unresolved_or_invalid_nested_json_pointer_is_rejected(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        references = (
            "#/base/$value/components/9",
            "#/base/$value/components/not-an-index",
            "#/base/$value/components/01",
            "#/base/$value/components/-",
            "#/base/$value/~2invalid",
        )
        for reference in references:
            document = {
                "base": {"$type": "color", "$value": color()},
                "derived": {
                    "$type": "color",
                    "$value": {
                        "colorSpace": "srgb",
                        "components": [
                            {"$ref": reference},
                            0.2,
                            0.3,
                        ],
                    },
                },
            }
            with self.subTest(reference=reference), self.assertRaises(DtcgValidationError):
                resolve_token_document(document)

    def test_nested_token_references_must_have_the_declared_subvalue_type(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        document = {
            "weight": {"$type": "fontWeight", "$value": 400},
            "family": {"$type": "fontFamily", "$value": "Inter"},
            "size": {"$type": "dimension", "$value": dimension(16)},
            "tracking": {"$type": "dimension", "$value": dimension(0)},
            "text": {
                "$type": "typography",
                "$value": {
                    "fontFamily": "{family}",
                    "fontSize": "{size}",
                    "fontWeight": "{weight}",
                    "letterSpacing": "{tracking}",
                    # The literal is a number but the referenced identity is not a number token.
                    "lineHeight": "{weight}",
                },
            },
        }

        with self.assertRaisesRegex(DtcgValidationError, "type mismatch"):
            resolve_token_document(document)

    def test_all_supported_types_accept_their_exact_normative_shapes(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        document = {
            "color": {"$type": "color", "$value": color()},
            "dimension": {"$type": "dimension", "$value": dimension()},
            "fontFamily": {"$type": "fontFamily", "$value": ["Inter", "sans-serif"]},
            "fontWeight": {"$type": "fontWeight", "$value": "semi-bold"},
            "duration": {"$type": "duration", "$value": {"value": 200, "unit": "ms"}},
            "cubicBezier": {"$type": "cubicBezier", "$value": [0, -1, 1, 2]},
            "number": {"$type": "number", "$value": -1.5},
            "strokeStyle": {
                "$type": "strokeStyle",
                "$value": {
                    "dashArray": [dimension(2), dimension(1, "rem")],
                    "lineCap": "round",
                },
            },
            "border": {
                "$type": "border",
                "$value": {"color": color(), "width": dimension(), "style": "solid"},
            },
            "transition": {
                "$type": "transition",
                "$value": {
                    "duration": {"value": 200, "unit": "ms"},
                    "delay": {"value": 0, "unit": "s"},
                    "timingFunction": [0.25, 0.1, 0.25, 1],
                },
            },
            "shadow": {
                "$type": "shadow",
                "$value": {
                    "color": color(alpha=0.5),
                    "offsetX": dimension(0),
                    "offsetY": dimension(2),
                    "blur": dimension(4),
                    "spread": dimension(0),
                    "inset": False,
                },
            },
            "gradient": {
                "$type": "gradient",
                "$value": [
                    {"color": color(0, 0, 0), "position": 0},
                    {"color": color(1, 1, 1), "position": 1},
                ],
            },
            "typography": {
                "$type": "typography",
                "$value": {
                    "fontFamily": "Inter",
                    "fontSize": dimension(16),
                    "fontWeight": 400,
                    "letterSpacing": dimension(0),
                    "lineHeight": 1.5,
                },
            },
        }

        self.assertEqual(set(resolve_token_document(document)), set(document))

    def test_every_supported_type_rejects_non_normative_values(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        invalid_values = {
            "number": True,
            "dimension": {"value": 1, "unit": "%"},
            "duration": {"value": 1, "unit": "frames"},
            "fontFamily": [],
            "fontWeight": "Bold",
            "cubicBezier": [1.1, 0, 0.5, 1],
            "color": {
                "colorSpace": "srgb",
                "components": [0, 1.1, 0],
                "alpha": 1.1,
            },
            "strokeStyle": {"dashArray": [dimension(1)], "lineCap": "flat"},
            "border": {"color": color(), "width": dimension(), "style": "unknown"},
            "transition": {
                "duration": {"value": 1, "unit": "ms"},
                "timingFunction": [0, 0, 1, 1],
            },
            "shadow": {
                "color": color(),
                "offsetX": dimension(),
                "offsetY": dimension(),
                "blur": dimension(),
                "spread": dimension(),
                "inset": "false",
            },
            "gradient": [{"color": color(), "position": "middle"}],
            "typography": {
                "fontFamily": "Inter",
                "fontSize": dimension(16),
                "fontWeight": 400,
                "letterSpacing": dimension(0),
                "lineHeight": dimension(24),
            },
        }

        for token_type, value in invalid_values.items():
            document = {"invalid": {"$type": token_type, "$value": value}}
            with self.subTest(token_type=token_type), self.assertRaises(DtcgValidationError):
                resolve_token_document(document)

    def test_composite_types_reject_unknown_members(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        values = {
            "color": {**color(), "fallback": "#ffffff"},
            "dimension": {**dimension(), "scale": 1},
            "strokeStyle": {
                "dashArray": [dimension()],
                "lineCap": "round",
                "lineJoin": "round",
            },
            "border": {
                "color": color(),
                "width": dimension(),
                "style": "solid",
                "radius": dimension(),
            },
            "transition": {
                "duration": {"value": 1, "unit": "ms"},
                "delay": {"value": 0, "unit": "ms"},
                "timingFunction": [0, 0, 1, 1],
                "property": "opacity",
            },
            "shadow": {
                "color": color(),
                "offsetX": dimension(),
                "offsetY": dimension(),
                "blur": dimension(),
                "spread": dimension(),
                "opacity": 1,
            },
            "typography": {
                "fontFamily": "Inter",
                "fontSize": dimension(16),
                "fontWeight": 400,
                "letterSpacing": dimension(0),
                "lineHeight": 1.5,
                "textTransform": "none",
            },
        }

        for token_type, value in values.items():
            with self.subTest(token_type=token_type), self.assertRaises(DtcgValidationError):
                resolve_token_document({"invalid": {"$type": token_type, "$value": value}})


if __name__ == "__main__":
    unittest.main()

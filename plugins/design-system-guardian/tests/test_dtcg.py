import unittest


class Dtcg2025ContractTest(unittest.TestCase):
    def test_types_aliases_root_and_deprecations_are_resolved_without_guessing(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        document = {
            "color": {
                "$type": "color",
                "$deprecated": "Use semantic colors.",
                "brand": {
                    "$root": {
                        "$value": {"colorSpace": "srgb", "components": [0.1, 0.2, 0.3]}
                    },
                    "alias": {"$value": "{color.brand.$root}", "$deprecated": False},
                    "pointer": {"$value": {"$ref": "#/color/brand/$root/$value"}},
                },
            }
        }

        tokens = resolve_token_document(document)
        self.assertIn("color.brand.$root", tokens)
        self.assertEqual(tokens["color.brand.alias"]["type"], "color")
        self.assertEqual(
            tokens["color.brand.alias"]["value"], tokens["color.brand.$root"]["value"]
        )
        self.assertEqual(tokens["color.brand.pointer"]["alias"], "color.brand.$root")
        self.assertTrue(tokens["color.brand.$root"]["deprecated"])
        self.assertFalse(tokens["color.brand.alias"]["deprecated"])

    def test_untyped_literal_is_invalid_and_type_is_never_inferred(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        with self.assertRaisesRegex(DtcgValidationError, "type"):
            resolve_token_document({"looks-like-color": {"$value": "#E6A700"}})

    def test_alias_cycles_unresolved_aliases_and_type_mismatch_fail(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        cases = [
            {"a": {"$value": "{b}"}, "b": {"$value": "{a}"}},
            {"a": {"$value": "{not-there}"}},
            {
                "a": {"$type": "color", "$value": "{b}"},
                "b": {"$type": "dimension", "$value": {"value": 4, "unit": "px"}},
            },
        ]
        for document in cases:
            with self.subTest(document=document), self.assertRaises(DtcgValidationError):
                resolve_token_document(document)

    def test_invalid_names_are_rejected(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        for name in ("$not-root", "has.dot", "has{brace", "has}brace"):
            with self.subTest(name=name), self.assertRaises(DtcgValidationError):
                resolve_token_document({name: {"$type": "number", "$value": 1}})

    def test_group_extends_deeply_inherits_and_cycles_fail(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, resolve_token_document

        document = {
            "base": {
                "$type": "dimension",
                "width": {"$value": {"value": 8, "unit": "px"}},
                "nested": {"height": {"$value": {"value": 4, "unit": "px"}}},
            },
            "large": {
                "$extends": "{base}",
                "width": {"$value": {"value": 16, "unit": "px"}},
            },
        }
        tokens = resolve_token_document(document)
        self.assertEqual(tokens["large.width"]["value"]["value"], 16)
        self.assertEqual(tokens["large.nested.height"]["value"]["value"], 4)

        with self.assertRaises(DtcgValidationError):
            resolve_token_document(
                {"a": {"$extends": "{b}"}, "b": {"$extends": "{a}"}}
            )

    def test_resolver_2025_contexts_are_explicit_and_validated(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        document = {
            "version": "2025.10",
            "modifiers": {
                "theme": {
                    "contexts": {"light": [], "dark": []},
                    "default": "light",
                }
            },
            "resolutionOrder": [{"$ref": "#/modifiers/theme"}],
        }
        evidence = validate_resolver_document(document, {"theme": "dark"})
        self.assertEqual(evidence["version"], "2025.10")
        self.assertEqual(evidence["contexts"], {"theme": "dark"})
        with self.assertRaises(DtcgValidationError):
            validate_resolver_document(document, {"theme": "blue"})


if __name__ == "__main__":
    unittest.main()

import unittest


class DtcgResolverStrictSchemaTest(unittest.TestCase):
    def test_inline_sets_and_modifiers_require_exact_shapes_names_and_types(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        invalid_items = (
            {"sources": []},
            {"name": "base", "sources": []},
            {"name": "base", "type": "collection", "sources": []},
            {"name": "base", "type": "set", "contexts": {"default": []}},
            {"name": "theme", "type": "modifier", "sources": []},
            {
                "name": "theme",
                "type": "modifier",
                "contexts": {"light": [], "dark": []},
                "unexpected": True,
            },
        )
        for item in invalid_items:
            with self.subTest(item=item), self.assertRaises(DtcgValidationError):
                validate_resolver_document(
                    {"version": "2025.10", "resolutionOrder": [item]},
                    {},
                )

        duplicate = {
            "version": "2025.10",
            "resolutionOrder": [
                {"name": "base", "type": "set", "sources": []},
                {"name": "base", "type": "modifier", "contexts": {"default": []}, "default": "default"},
            ],
        }
        with self.assertRaisesRegex(DtcgValidationError, "duplicate"):
            validate_resolver_document(duplicate, {})

    def test_named_sets_and_modifiers_have_exact_shapes(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        invalid_documents = (
            {
                "version": "2025.10",
                "sets": {"": {"sources": []}},
                "resolutionOrder": [],
            },
            {
                "version": "2025.10",
                "sets": {"base": {"sources": [], "type": "set"}},
                "resolutionOrder": [],
            },
            {
                "version": "2025.10",
                "modifiers": {"theme": {"contexts": {}, "default": "light"}},
                "resolutionOrder": [],
            },
            {
                "version": "2025.10",
                "modifiers": {"theme": {"contexts": {"": []}, "default": ""}},
                "resolutionOrder": [],
            },
            {
                "version": "2025.10",
                "modifiers": {"theme": {"contexts": {"light": []}, "sources": []}},
                "resolutionOrder": [],
            },
            {
                "version": "2025.10",
                "name": 7,
                "resolutionOrder": [],
            },
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(DtcgValidationError):
                validate_resolver_document(document, {})

    def test_reference_permissions_and_target_types_are_position_sensitive(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document

        base = {
            "version": "2025.10",
            "sets": {"base": {"sources": []}},
            "modifiers": {
                "theme": {
                    "contexts": {"light": [], "dark": []},
                    "default": "light",
                }
            },
            "resolutionOrder": [{"$ref": "#/sets/base"}],
        }
        validate_resolver_document(base, {"theme": "dark"})

        invalid_references = (
            ("set-to-modifier", {"sets": {"bad": {"sources": [{"$ref": "#/modifiers/theme"}]}}}),
            (
                "modifier-to-modifier",
                {
                    "modifiers": {
                        "theme": {
                            "contexts": {"light": [{"$ref": "#/modifiers/theme"}], "dark": []},
                            "default": "light",
                        }
                    }
                },
            ),
            ("order-to-set-member", {"resolutionOrder": [{"$ref": "#/sets/base/sources"}]}),
            (
                "order-to-modifier-context",
                {"resolutionOrder": [{"$ref": "#/modifiers/theme/contexts/dark"}]},
            ),
            ("order-to-order", {"resolutionOrder": [{"$ref": "#/resolutionOrder/0"}]}),
        )

        for name, override in invalid_references:
            document = {
                **base,
                **override,
                "sets": {**base["sets"], **override.get("sets", {})},
                "modifiers": {**base["modifiers"], **override.get("modifiers", {})},
            }
            with self.subTest(name=name), self.assertRaises(DtcgValidationError):
                validate_resolver_document(document, {"theme": "dark"})

    def test_inline_modifier_participates_in_input_validation_and_materialization(self) -> None:
        from guardian_core.dtcg import DtcgValidationError, validate_resolver_document
        from guardian_core.dtcg_resolver import materialize_resolver_tokens

        resolver = {
            "version": "2025.10",
            "resolutionOrder": [
                {
                    "name": "theme",
                    "type": "modifier",
                    "contexts": {
                        "light": [{"surface": {"$type": "number", "$value": 1}}],
                        "dark": [{"surface": {"$type": "number", "$value": 0}}],
                    },
                }
            ],
        }

        with self.assertRaisesRegex(DtcgValidationError, "Missing required"):
            validate_resolver_document(resolver, {})
        result = materialize_resolver_tokens({}, resolver, {"theme": "dark"})
        self.assertEqual(result["tokens"]["surface"]["value"], 0)
        self.assertEqual(result["evidence"]["contexts"], {"theme": "dark"})

    def test_rfc6901_escaped_set_name_materializes(self) -> None:
        from guardian_core.dtcg_resolver import materialize_resolver_tokens

        resolver = {
            "version": "2025.10",
            "sets": {
                "base/foundation": {
                    "sources": [{"space": {"$type": "number", "$value": 4}}]
                }
            },
            "resolutionOrder": [{"$ref": "#/sets/base~1foundation"}],
        }

        result = materialize_resolver_tokens({}, resolver, {})
        self.assertEqual(result["tokens"]["space"]["value"], 4)


if __name__ == "__main__":
    unittest.main()

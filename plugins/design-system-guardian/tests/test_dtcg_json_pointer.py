import unittest


class DtcgJsonPointerTest(unittest.TestCase):
    def test_normative_token_pointer_and_property_value_pointer_resolve(self) -> None:
        from guardian_core.dtcg import resolve_token_document

        document = {
            "base": {"$type": "number", "$value": 4},
            "alias": {"$ref": "#/base"},
            "propertyAlias": {"$value": {"$ref": "#/base/$value"}},
        }
        tokens = resolve_token_document(document)
        self.assertEqual(tokens["alias"]["alias"], "base")
        self.assertEqual(tokens["propertyAlias"]["alias"], "base")
        self.assertEqual(tokens["alias"]["value"], 4)


if __name__ == "__main__":
    unittest.main()

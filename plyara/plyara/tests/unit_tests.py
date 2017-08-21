# coding=utf-8
import unittest
from plyara import YaraParser

parser = YaraParser()

UnhandledRuleMsg = "Unhandled Test Rule: {}"

class TestRuleParser(unittest.TestCase):

    def test_multiple_rules(self):
        with open('plyara/tests/data/mixed_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)
        self.assertEqual(len(result), 1)

    def test_import_pe(self):
        with open('plyara/tests/data/import_ruleset_pe.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"pe"' in rule['imports'])

    def test_import_elf(self):
        with open('plyara/tests/data/import_ruleset_elf.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"elf"' in rule['imports'])

    def test_import_cuckoo(self):
        with open('plyara/tests/data/import_ruleset_cuckoo.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"cuckoo"' in rule['imports'])

    def test_import_magic(self):
        with open('plyara/tests/data/import_ruleset_magic.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"magic"' in rule['imports'])

    def test_import_hash(self):
        with open('plyara/tests/data/import_ruleset_hash.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"hash"' in rule['imports'])

    def test_import_math(self):
        with open('plyara/tests/data/import_ruleset_math.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"math"' in rule['imports'])

    def test_import_dotnet(self):
        with open('plyara/tests/data/import_ruleset_dotnet.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"dotnet"' in rule['imports'])

    def test_import_androguard(self):
        with open('plyara/tests/data/import_ruleset_androguard.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for rule in result:
            self.assertTrue('"androguard"' in rule['imports'])

    def test_scopes(self):
        with open('plyara/tests/data/scope_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "GlobalScope":
                self.assertTrue('global' in entry['scopes'])

            elif rulename == "PrivateScope":
                self.assertTrue('private' in entry['scopes'])

            elif rulename == "PrivateGlobalScope":
                self.assertTrue('global' in entry['scopes'] and
                                'private' in entry['scopes'])
            else:
                raise AssertionError(UnhandledRuleMsg.format(rulename))

    def test_tags(self):
        with open('plyara/tests/data/tag_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "OneTag":
                self.assertTrue(len(entry['tags']) == 1 and
                                'tag1' in entry['tags'])

            elif rulename == "TwoTags":
                self.assertTrue(len(entry['tags']) == 2 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'])

            elif rulename == "ThreeTags":
                self.assertTrue(len(entry['tags']) == 3 and
                                'tag1' in entry['tags'] and
                                'tag2' in entry['tags'] and
                                'tag3' in entry['tags'])

            else:
                raise AssertionError(UnhandledRuleMsg.format(rulename))

    def test_metadata(self):
        with open('plyara/tests/data/metadata_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "StringTypeMetadata":
                self.assertTrue('string_value' in entry['metadata'] and
                                entry['metadata']['string_value'] == '\"String Metadata\"')

            elif rulename == "IntegerTypeMetadata":
                self.assertTrue('integer_value' in entry['metadata'] and
                                entry['metadata']['integer_value'] == '100')

            elif rulename == "BooleanTypeMetadata":
                self.assertTrue('boolean_value' in entry['metadata'] and
                                entry['metadata']['boolean_value'] == 'true')

            elif rulename == "AllTypesMetadata":
                self.assertTrue('string_value' in entry['metadata'] and
                                'integer_value' in entry['metadata'] and
                                'boolean_value' in entry['metadata'] and
                                entry['metadata']['string_value'] == '\"Different String Metadata\"' and
                                entry['metadata']['integer_value'] == '33' and
                                entry['metadata']['boolean_value'] == 'false')

            else:
                raise AssertionError(UnhandledRuleMsg.format(rulename))

    def test_strings(self):
        with open('plyara/tests/data/string_ruleset.yar', 'r') as f:
            inputString = f.read()

        result = parser.run(inputString)

        for entry in result:
            rulename = entry['rule_name']

            if rulename == "Text":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"')])

            elif rulename == "FullwordText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"', ['fullword'])])

            elif rulename == "CaseInsensitiveText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$text_string', '\"foobar\"', ['nocase'])])

            elif rulename == "WideCharText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$wide_string', '\"Borland\"', ['wide'])])

            elif rulename == "WideCharAsciiText":
                self.assertTrue([(s['name'], s['value'], s['modifiers'])
                                for s in entry['strings']] ==
                                [('$wide_and_ascii_string', '\"Borland\"', ['wide', 'ascii'])])

            elif rulename == "HexWildcard":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ E2 34 ?? C8 A? FB }')])

            elif rulename == "HexJump":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 [4-6] 62 B4 }')])

            elif rulename == "HexAlternatives":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 ( 62 B4 | 56 ) 45 }')])

            elif rulename == "HexMultipleAlternatives":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$hex_string', '{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }')])

            elif rulename == "RegExp":
                self.assertTrue([(s['name'], s['value'])
                                for s in entry['strings']] ==
                                [('$re1', '/md5: [0-9a-fA-F]{32}/'),
                                 ('$re2', '/state: (on|off)/')])

            else:
                raise AssertionError(UnhandledRuleMsg.format(rulename))

if __name__ == '__main__':
    unittest.main()

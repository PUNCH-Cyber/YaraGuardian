# coding=utf-8
import unittest

from plyara import YaraParser

parser = YaraParser()


class TestYaraRules(unittest.TestCase):

    def test_multiple_rules(self):

        inputString = r'''

        rule FirstRule {
            meta:
                author = "Andrés Iniesta"
                date = "2015-01-01"
            strings:
                $a = "hark, a \"string\" here" fullword ascii
                $b = { 00 22 44 66 88 aa cc ee }
            condition:
                all of them
        }

        import "bingo"
        import "bango"

        rule SecondRule : aTag {
            meta:
                author = "Ivan Rakitić"
                date = "2015-02-01"
            strings:
                $x = "hi"
                $y = /state: (on|off)/ wide
                $z = "bye"
            condition:
                for all of them : ( # > 2 )
        }

        rule ThirdRule {condition: uint32(0) == 0xE011CFD0}
        '''

        result = parser.run(inputString)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]['metadata']['author'], '"Andrés Iniesta"')
        self.assertEqual(result[0]['metadata']['date'], '"2015-01-01"')
        self.assertTrue([x["name"] for x in result[0]['strings']] == ['$a', '$b'])

    def test_rule_name_imports_and_scopes(self):

        inputStringNIS = r'''
            rule four {meta: i = "j" strings: $a = "b" condition: true }
            global rule five {meta: i = "j" strings: $a = "b" condition: false }
            private rule six {meta: i = "j" strings: $a = "b" condition: true }
            global private rule seven {meta: i = "j" strings: $a = "b" condition: true }
            import "lib1"
            rule eight {meta: i = "j" strings: $a = "b" condition: true }
            import "lib1"
            import "lib2"
            rule nine {meta: i = "j" strings: $a = "b" condition: true }
            import "lib1"
            import "lib2"
            private global rule ten {meta: i = "j" strings: $a = "b" condition: true }
        '''

        result = parser.run(inputStringNIS)

        self.assertEqual(len(result), 7)

        for rule in result:
            rule_name = rule["rule_name"]

            if rule_name == 'four':
                self.assertTrue('scopes' not in rule)
                self.assertTrue('imports' not in rule)
            if rule_name == 'five':
                self.assertTrue('imports' not in rule)
                self.assertTrue('global' in rule['scopes'])
            if rule_name == 'six':
                self.assertTrue('imports' not in rule)
                self.assertTrue('private' in rule['scopes'])
            if rule_name == 'seven':
                self.assertTrue('imports' not in rule)
                self.assertTrue('private' in rule['scopes'] and 'global' in rule['scopes'])
            if rule_name == 'eight':
                self.assertTrue('"lib1"' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'nine':
                self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
                self.assertTrue('scopes' not in rule)
            if rule_name == 'ten':
                self.assertTrue('"lib1"' in rule['imports'] and '"lib2"' in rule['imports'])
                self.assertTrue('global' in rule['scopes'] and 'private' in rule['scopes'])

    def test_tags(self):

        inputTags = r'''
            rule eleven: tag1 {meta: i = "j" strings: $a = "b" condition: true }
            rule twelve : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        result = parser.run(inputTags)

        for rule in result:
            rule_name = rule["rule_name"]

            if rule_name == 'eleven':
                self.assertTrue(len(rule['tags']) == 1 and
                                'tag1' in rule['tags'])

            if rule_name == 'twelve':
                self.assertTrue(len(rule['tags']) == 2 and
                                'tag1' in rule['tags'] and
                                'tag2' in rule['tags'])


if __name__ == '__main__':
    unittest.main()

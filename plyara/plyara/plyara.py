import re
import hashlib
import ply.lex as lex
import ply.yacc as yacc
from collections import deque

# Derived from https://github.com/8u1a/plyara


class ElementTypes:
    """
    An enumeration of the element types emitted by
    the parser to the interpreter
    """
    RULE_NAME = 1
    METADATA_KEY_VALUE = 2
    STRINGS_KEY_VALUE = 3
    STRINGS_MODIFIER = 4
    IMPORT = 5
    TERM = 6
    SCOPE = 7
    TAG = 8
    INCLUDE = 9
    COMMENT = 10
    MCOMMENT = 11


class ParserInterpreter:
    """
    Interpret the output of the parser and produce an
    alternative representation of Yara rules
    """

    rules = deque()

    currentRule = {}

    stringModifiersAccumulator = []
    importsAccumulator = []
    includesAccumulator = []
    termAccumulator = []
    scopeAccumulator = []
    tagAccumulator = []
    commentAccumulator = []

    isPrintDebug = False

    comparison_operators = ('==', '!=', '>', '<', '>=', '<=')

    import_options = ('pe',
                      'elf',
                      'cuckoo',
                      'magic',
                      'hash',
                      'math',
                      'dotnet',
                      'androguard')

    keywords = ('all', 'and', 'any', 'ascii', 'at', 'condition',
                'contains', 'entrypoint', 'false', 'filesize',
                'fullword', 'for', 'global', 'in', 'import',
                'include', 'int8', 'int16', 'int32', 'int8be',
                'int16be', 'int32be', 'matches', 'meta', 'nocase',
                'not', 'or', 'of', 'private', 'rule', 'strings',
                'them', 'true', 'uint8', 'uint16', 'uint32', 'uint8be',
                'uint16be', 'uint32be', 'wide')

    function_keywords = ('uint8', 'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be')

    def reset(self):
        self.rules.clear()

        self.currentRule = {}

        self.stringModifiersAccumulator = []
        self.importsAccumulator = []
        self.includesAccumulator = []
        self.termAccumulator = []
        self.scopeAccumulator = []
        self.tagAccumulator = []
        self.commentAccumulator = []

        self.isPrintDebug = False

    def addElement(self, elementType, elementValue):
        """
        Accepts elements from the parser and uses them to
        construct a representation of the Yara rule
        """

        if elementType == ElementTypes.RULE_NAME:
            self.currentRule["rule_name"] = elementValue
            self.readAndResetAccumulators()
            self.rules.append(self.currentRule)

            if self.isPrintDebug:
                print("--Adding Rule " + self.currentRule['rule_name'])

            self.currentRule = {}

        elif elementType == ElementTypes.METADATA_KEY_VALUE:
            if "metadata" not in self.currentRule:
                self.currentRule["metadata"] = {elementValue[0]: elementValue[1]}
            else:
                if elementValue[0] not in self.currentRule["metadata"]:
                    self.currentRule["metadata"][elementValue[0]] = elementValue[1]
                else:
                    if isinstance(self.currentRule["metadata"][elementValue[0]], list):
                        self.currentRule["metadata"][elementValue[0]].append(elementValue[1])
                    else:
                        self.currentRule["metadata"][elementValue[0]] = [self.currentRule["metadata"][elementValue[0]], elementValue[1]]

        elif elementType == ElementTypes.STRINGS_KEY_VALUE:
            string_dict = {'name': elementValue[0], 'value': elementValue[1]}

            if len(self.stringModifiersAccumulator)  > 0:
                string_dict["modifiers"] = self.stringModifiersAccumulator
                self.stringModifiersAccumulator = []

            if "strings" not in self.currentRule:
                self.currentRule["strings"] = [string_dict]
            else:
                self.currentRule["strings"].append(string_dict)

        elif elementType == ElementTypes.STRINGS_MODIFIER:
            self.stringModifiersAccumulator.append(elementValue)

        elif elementType == ElementTypes.IMPORT:
            self.importsAccumulator.append(elementValue)

        elif elementType == ElementTypes.INCLUDE:
            self.includesAccumulator.append(elementValue)

        elif elementType == ElementTypes.TERM:
            self.termAccumulator.append(elementValue)

        elif elementType == ElementTypes.SCOPE:
            self.scopeAccumulator.append(elementValue)

        elif elementType == ElementTypes.TAG:
            self.tagAccumulator.append(elementValue)

        elif elementType == ElementTypes.COMMENT:
            self.commentAccumulator.append(elementValue)

        elif elementType == ElementTypes.MCOMMENT:
            self.commentAccumulator.append(elementValue)

    def readAndResetAccumulators(self):
        """
        Adds accumulated elements to the current
        rule and resets the accumulators
        """
        if len(self.importsAccumulator) > 0:
            self.currentRule["imports"] = self.importsAccumulator
            self.importsAccumulator = []

        if len(self.includesAccumulator) > 0:
            self.currentRule["includes"] = self.includesAccumulator
            self.includesAccumulator = []

        if len(self.termAccumulator) > 0:
            self.currentRule["condition_terms"] = self.termAccumulator
            self.termAccumulator = []

        if len(self.scopeAccumulator) > 0:
            self.currentRule["scopes"] = self.scopeAccumulator
            self.scopeAccumulator = []

        if len(self.tagAccumulator) > 0:
            self.currentRule["tags"] = self.tagAccumulator
            self.tagAccumulator = []

        if len(self.commentAccumulator) > 0:
            self.currentRule["comments"] = self.commentAccumulator
            self.commentAccumulator = []

    def printDebugMessage(self, message):
        """
        Prints a debug message emitted by the parser
        if self.isPrintDebug is True
        """
        if self.isPrintDebug:
            print(message)

        return True

    def isValidRuleName(self, entry):
        """
        Checks to see if entry is a valid rule name
        """
        # Check if entry is blank
        if not entry:
            return False

        # Check length
        if len(entry) > 128:
            return False

        # Ensure doesn't start with a digit
        if entry[0].isdigit():
            return False

        # Accept only alphanumeric and underscores
        if not re.match(r'\w+$', entry):
            return False

        # Verify not in keywords
        if entry in self.keywords:
            return False

        return True

    def isValidRuleTag(self, entry):
        """
        Checks to see if entry is a valid rule tag
        """
        return self.isValidRuleName(entry)  # Same lexical conventions as name

    def detectImports(self, rule):
        """
        Takes a parsed yararule and provide a list of required imports based on condition
        """
        detected_imports = []
        condition_terms = rule['condition_terms']

        for imp in self.import_options:
            imp_string = "\"{}\"".format(imp)
            imp_module = "{}.".format(imp)

            if imp in condition_terms and imp_string not in detected_imports:
                detected_imports.append(imp_string)

            elif imp_string not in detected_imports:
                for term in condition_terms:
                    if term.startswith(imp_module):
                        detected_imports.append(imp_string)
                        break
            else:
                pass

        return detected_imports

    def detectDependencies(self, rule):
        """
        Takes a parsed yararule and provide a list of external rule dependencies
        """
        dependencies = []
        condition_terms = rule['condition_terms']

        # Container for any iteration string references
        string_iteration_variables = []

        # Number of terms for index iteration and reference
        term_count = len(condition_terms)

        # Check for rule dependencies within condition
        for index in range(0, term_count):
            # Grab term by index
            term = condition_terms[index]

            if self.isValidRuleName(term) and (term not in self.import_options):
                # Grab reference to previous term for logic checks
                if index > 0:
                    previous_term = condition_terms[index - 1]
                else:
                    previous_term = None

                # Grab reference to next term for logic checks
                if index < (term_count - 1):
                    next_term = condition_terms[index + 1]
                else:
                    next_term = None

                # Import and androguard functions will have a lot going on while
                # a simple rule reference should be preceded or followed by a connecting
                # keyword or be by itself
                if (previous_term or next_term) and (next_term not in ('and', 'or')) and (previous_term not in ('and', 'or')):
                    continue

                # Check if reference is a variable for string iteration
                if term in string_iteration_variables:
                    continue

                # Check if reference is a variable for string iteration
                if previous_term in ('any', 'all') and next_term == 'in':
                    string_iteration_variables.append(term)
                    continue

                # Check if term is a filesize reference
                if term in ('MB', 'KB'):
                    try:
                        int(previous_term)
                    except ValueError:
                        pass
                    else:
                        continue

                # Check for external string variable dependency
                if ((next_term in ('matches', 'contains')) or (previous_term in ('matches', 'contains'))):
                    continue

                # Check for external integer variable dependency
                if ((next_term in self.comparison_operators) or (previous_term in self.comparison_operators)):
                    continue

                # Check for external boolean dependency may not be possible without stripping out valid rule references

                dependencies.append(term)

        return dependencies

    def generateLogicHash(self, rule):
        """
        Calculate hash value of rule strings and condition
        """
        strings = rule.get('strings', [])
        sorted_strings = sorted([s['value'] for s in strings])
        sorted_strings.extend(rule['condition_terms'])
        logic_hash = hashlib.sha1(''.join(sorted_strings).encode()).hexdigest()
        return logic_hash

    def rebuildYaraRule(self, rule):
        """
        Take a parsed yararule and rebuild it into a usable one
        """

        rule_format = "{imports}{scopes}rule {rulename}{tags} {{\n{meta}{strings}{condition}\n}}\n"

        rule_name = rule['rule_name']

        # Rule Imports
        if rule['imports']:
            unpacked_imports = ['import {}\n'.format(entry) for entry in rule['imports']]
            rule_imports = '{}\n'.format(''.join(unpacked_imports))
        else:
            rule_imports = ''

        # Rule Scopes
        if rule['scopes']:
            rule_scopes = '{} '.format(' '.join(rule['scopes']))
        else:
            rule_scopes = ''

        # Rule Tags
        if rule['tags']:
            rule_tags = ' : {}'.format(' '.join(rule['tags']))
        else:
            rule_tags = ''

        # Rule Metadata
        if rule['metadata']:
            unpacked_meta = ['\n\t\t{key} = {value}'.format(key=k, value=v)
                             for k, v in rule['metadata'].items()]
            rule_meta = '\n\tmeta:{}\n'.format(''.join(unpacked_meta))
        else:
            rule_meta = ''

        # Rule Strings
        if rule['strings']:

            string_container = []

            for rule_string in rule['strings']:

                if 'modifiers' in rule_string:
                    string_modifiers = ' '.join(rule_string['modifiers'])

                    fstring = '\n\t\t{} = {} {}'.format(rule_string['name'],
                                                        rule_string['value'],
                                                        string_modifiers)
                else:
                    fstring = '\n\t\t{} = {}'.format(rule_string['name'],
                                                     rule_string['value'])

                string_container.append(fstring)

            rule_strings = '\n\tstrings:{}\n'.format(''.join(string_container))
        else:
            rule_strings = ''

        if rule['condition_terms']:
            # Format condition with appropriate whitespace between keywords
            cond = []

            for term in rule['condition_terms']:

                if not cond:

                    if term in self.function_keywords:
                        cond.append(term)

                    elif term in self.keywords:
                        cond.append(term)
                        cond.append(' ')

                    else:
                        cond.append(term)

                else:

                    if cond[-1] == ' ' and term in self.function_keywords:
                        cond.append(term)

                    elif cond and cond[-1] != ' ' and term in self.function_keywords:
                        cond.append(' ')
                        cond.append(term)

                    elif cond[-1] == ' ' and term in self.keywords:
                        cond.append(term)
                        cond.append(' ')

                    elif cond and cond[-1] != ' ' and term in self.keywords:
                        cond.append(' ')
                        cond.append(term)
                        cond.append(' ')

                    else:
                        cond.append(term)

            fcondition = ''.join(cond)
            rule_condition = '\n\tcondition:\n\t\t{}'.format(fcondition)
        else:
            rule_condition = ''

        formatted_rule = rule_format.format(imports=rule_imports,
                                            rulename=rule_name,
                                            tags=rule_tags,
                                            meta=rule_meta,
                                            scopes=rule_scopes,
                                            strings=rule_strings,
                                            condition=rule_condition)

        return formatted_rule


class YaraLexerModule(object):

    tokens = [
        'BYTESTRING',
        'STRING',
        'REXSTRING',
        'EQUALS',
        'STRINGNAME',
        'STRINGNAME_ARRAY',
        'LPAREN',
        'RPAREN',
        'LBRACK',
        'RBRACK',
        'LBRACE',
        'RBRACE',
        'ID',
        'BACKSLASH',
        'FORWARDSLASH',
        'PIPE',
        'PLUS',
        'SECTIONMETA',
        'SECTIONSTRINGS',
        'SECTIONCONDITION',
        'COMMA',
        'STRINGCOUNT',
        'GREATERTHAN',
        'LESSTHAN',
        'GREATEREQUAL',
        'LESSEQUAL',
        'RIGHTBITSHIFT',
        'LEFTBITSHIFT',
        'MODULO',
        'TILDE',
        'XOR',
        'PERIOD',
        'COLON',
        'STAR',
        'HYPHEN',
        'AMPERSAND',
        'NEQUALS',
        'EQUIVALENT',
        'DOTDOT',
        'HEXNUM',
        'NUM',
        'COMMENT',
        'MCOMMENT'
    ]

    reserved = {
        'all': 'ALL',
        'and': 'AND',
        'any': 'ANY',
        'ascii': 'ASCII',
        'at': 'AT',
        'contains': 'CONTAINS',
        'entrypoint': 'ENTRYPOINT',
        'false': 'FALSE',
        'filesize': 'FILESIZE',
        'for': 'FOR',
        'fullword': 'FULLWORD',
        'global': 'GLOBAL',
        'import': 'IMPORT',
        'in': 'IN',
        'include' : 'INCLUDE',
        'int8': 'INT8',
        'int16': 'INT16',
        'int32': 'INT32',
        'int8be': 'INT8BE',
        'int16be': 'INT16BE',
        'int32be': 'INT32BE',
        'matches': 'MATCHES',
        'nocase': 'NOCASE',
        'not': 'NOT',
        'of': 'OF',
        'or': 'OR',
        'private': 'PRIVATE',
        'rule': 'RULE',
        'them': 'THEM',
        'true': 'TRUE',
        'wide': 'WIDE',
        'uint8': 'UINT8',
        'uint16': 'UINT16',
        'uint32': 'UINT32',
        'uint8be': 'UINT8BE',
        'uint16be': 'UINT16BE',
        'uint32be': 'UINT32BE',
    }

    tokens = tokens + list(reserved.values())

    # Simple tokens
    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_EQUIVALENT = r'=='
    t_NEQUALS = r'!='
    t_EQUALS = r'='
    t_LBRACE = r'{'
    t_RBRACE = r'}'
    t_PLUS = r'\+'
    t_PIPE = r'\|'
    t_BACKSLASH = r'\\'
    t_FORWARDSLASH = r'/'
    t_COMMA = r','
    t_GREATERTHAN = r'>'
    t_LESSTHAN = r'<'
    t_GREATEREQUAL = r'>='
    t_LESSEQUAL = r'<='
    t_RIGHTBITSHIFT = r'>>'
    t_LEFTBITSHIFT = r'<<'
    t_MODULO = r'%'
    t_TILDE = r'~'
    t_XOR = r'\^'
    t_PERIOD = r'\.'
    t_COLON = r':'
    t_STAR = r'\*'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_HYPHEN = r'\-'
    t_AMPERSAND = r'&'
    t_DOTDOT = r'\.\.'

    def t_COMMENT(self, t):
        r'(//.*)(?=\n)'
        return t

    # http://comments.gmane.org/gmane.comp.python.ply/134
    def t_MCOMMENT(self, t):
        # r'/\*(.|\n)*?\*/'
        r'/\*(.|\n|\r|\r\n)*?\*/'
        if '\r\n' in t.value:
            t.lineno += t.value.count('\r\n')
        else:
            t.lineno += t.value.count('\n')
        return t

    # Define a rule so we can track line numbers
    def t_NEWLINE(self, t):
        # r'\n+'
        r'(\n|\r|\r\n)+'
        t.lexer.lineno += len(t.value)
        t.value = t.value
        pass

    def t_HEXNUM(self, t):
        r'0x[A-Fa-f0-9]+'
        t.value = t.value
        return t

    def t_SECTIONMETA(self, t):
        r'meta:|meta[\s]+:'
        t.value = t.value
        return t

    def t_SECTIONSTRINGS(self, t):
        r'strings:|strings[\s]+:'
        t.value = t.value
        return t

    def t_SECTIONCONDITION(self, t):
        r'condition:|condition[\s]+:'
        t.value = t.value
        return t

    def t_STRING(self, t):
        # r'".+?"(?<![^\\]\\")'
        r'".+?"(?<![^\\]\\")(?<![^\\][\\]{3}")(?<![^\\][\\]{5}")'
        t.value = t.value
        return t

    def t_BYTESTRING(self, t):
        r'\{[\|\(\)\[\]\-\?a-fA-F0-9\s]+\}'
        t.value = t.value
        return t

    def t_REXSTRING(self, t):
        r'\/.+\/(?=\s|$)'
        t.value = t.value
        return t

    def t_STRINGNAME(self, t):
        r'\$[0-9a-zA-Z\-_*]*'
        t.value = t.value
        return t

    def t_STRINGNAME_ARRAY(self, t):
        r'@[0-9a-zA-Z\-_*]*'
        t.value = t.value
        return t

    def t_NUM(self, t):
        r'\d+(\.\d+)?|0x\d+'
        t.value = t.value
        return t

    def t_ID(self, t):
        r'[a-zA-Z_]{1}[a-zA-Z_0-9.]*'
        t.type = self.reserved.get(t.value, 'ID')  # Check for reserved words
        return t

    def t_STRINGCOUNT(self, t):
        r'\#[^\s]*'
        t.value = t.value
        return t

    # A string containing ignored characters (spaces and tabs)
    #t_ignore = ' \t\r\n'
    t_ignore = ' \t'

    # Error handling rule
    def t_error(self, t):
        raise TypeError("Illegal character " + t.value[0] + " at line " + str(t.lexer.lineno))
        t.lexer.skip(1)

    precedence = (('right', 'NUM'), ('right', 'ID'), ('right', 'HEXNUM'))


def yara_token_generator(data):
    lexer = lex.lex(module=YaraLexerModule())
    lexer.input(data)

    while True:
        tok = lexer.token()

        if not tok:
            break

        yield tok


class YaraParser(object):

    parserInterpreter = ParserInterpreter()

    def __init__(self):
        self.tokens = YaraLexerModule.tokens
        self.lexer = lex.lex(module=YaraLexerModule())

        self.parser = None  # attribute placeholder until build funct is called
        self.parser_error = {} # attribute placeholder in case error encountered

        self.rule_comments = deque()

    def p_rules(self, p):
        '''rules : rules rule
                 | rule'''

    def p_rule(self, p):
        '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''
        self.parserInterpreter.printDebugMessage('matched rule ' + str(p[3]))

        while self.rule_comments:
            comment = self.rule_comments.pop()

            if p.lexpos(5) < comment.lexpos < p.lexpos(7):
                self.parserInterpreter.addElement(getattr(ElementTypes, comment.type), comment.value)

        self.parserInterpreter.addElement(ElementTypes.RULE_NAME, str(p[3]))

    def p_imports_and_scopes(self, p):
        '''imports_and_scopes : imports
                              | includes
                              | scopes
                              | imports scopes
                              | includes scopes
                              | '''

    def p_imports(self, p):
        '''imports : imports import
                   | includes
                   | import'''

    def p_includes(self, p):
        '''includes : includes include
                    | imports
                    | include'''

    def p_import(self, p):
        'import : IMPORT STRING'
        self.parserInterpreter.printDebugMessage('...matched import ' + p[2])
        self.parserInterpreter.addElement(ElementTypes.IMPORT, p[2])

    def p_include(self, p):
        'include : INCLUDE STRING'
        self.parserInterpreter.printDebugMessage('...matched include ' + p[2])
        self.parserInterpreter.addElement(ElementTypes.INCLUDE, p[2])

    def p_scopes(self, p):
        '''scopes : scopes scope
                  | scope'''

    def p_tag_section(self, p):
        '''tag_section : COLON tags
                       | '''

    def p_tags(self, p):
        '''tags : tags tag
                | tag'''

    def p_tag(self, p):
        'tag : ID'
        self.parserInterpreter.printDebugMessage('matched tag ' + str(p[1]))
        self.parserInterpreter.addElement(ElementTypes.TAG, p[1])

    def p_scope(self, p):
        '''scope : PRIVATE
                 | GLOBAL'''
        self.parserInterpreter.printDebugMessage('matched scope identifier ' + str(p[1]))
        self.parserInterpreter.addElement(ElementTypes.SCOPE, p[1])

    def p_rule_body(self, p):
        'rule_body : sections'
        self.parserInterpreter.printDebugMessage('...matched rule body')

    def p_rule_sections(self, p):
        '''sections : sections section
                  | section'''

    def p_rule_section(self, p):
        '''section : meta_section
                   | strings_section
                   | condition_section'''

    def p_meta_section(self, p):
        'meta_section : SECTIONMETA meta_kvs'
        self.parserInterpreter.printDebugMessage('...matched meta section')

    def p_strings_section(self, p):
        'strings_section : SECTIONSTRINGS strings_kvs'

    def p_condition_section(self, p):
        'condition_section : SECTIONCONDITION expression'

    # Meta elements.

    def p_meta_kvs(self, p):
        '''meta_kvs : meta_kvs meta_kv
                    | meta_kv'''
        self.parserInterpreter.printDebugMessage('...matched meta kvs')

    def p_meta_kv(self, p):
        '''meta_kv : ID EQUALS STRING
                   | ID EQUALS ID
                   | ID EQUALS TRUE
                   | ID EQUALS FALSE
                   | ID EQUALS NUM'''
        key = str(p[1])
        value = str(p[3])
        self.parserInterpreter.printDebugMessage('matched meta kv: ' + key + " equals " + value)
        self.parserInterpreter.addElement(ElementTypes.METADATA_KEY_VALUE, (key, value))

    # Strings elements.

    def p_strings_kvs(self, p):
        '''strings_kvs : strings_kvs strings_kv
                       | strings_kv'''
        self.parserInterpreter.printDebugMessage('...matched strings kvs')

    def p_strings_kv(self, p):
        '''strings_kv : STRINGNAME EQUALS STRING
                      | STRINGNAME EQUALS STRING string_modifiers
                      | STRINGNAME EQUALS BYTESTRING
                      | STRINGNAME EQUALS REXSTRING
                      | STRINGNAME EQUALS REXSTRING string_modifiers'''

        key = str(p[1])
        value = str(p[3])
        self.parserInterpreter.printDebugMessage('matched strings kv: ' + key + " equals " + value)
        self.parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, (key, value))

    def p_string_modifers(self, p):
        '''string_modifiers : string_modifiers string_modifier
                            | string_modifier'''

    def p_string_modifier(self, p):
        '''string_modifier : NOCASE
                           | ASCII
                           | WIDE
                           | FULLWORD'''
        self.parserInterpreter.printDebugMessage('...matched a string modifier: ' + p[1])
        self.parserInterpreter.addElement(ElementTypes.STRINGS_MODIFIER, p[1])


    # Condition elements.
    def p_expression(self, p):
        '''expression : expression term
                      | term'''

    def p_condition(self, p):
        '''term : ID
                | STRING
                | NUM
                | HEXNUM
                | LPAREN
                | RPAREN
                | LBRACK
                | RBRACK
                | DOTDOT
                | EQUIVALENT
                | EQUALS
                | NEQUALS
                | PLUS
                | PIPE
                | BACKSLASH
                | FORWARDSLASH
                | COMMA
                | GREATERTHAN
                | LESSTHAN
                | GREATEREQUAL
                | LESSEQUAL
                | RIGHTBITSHIFT
                | LEFTBITSHIFT
                | MODULO
                | TILDE
                | XOR
                | PERIOD
                | COLON
                | STAR
                | HYPHEN
                | AMPERSAND
                | ALL
                | AND
                | ANY
                | AT
                | CONTAINS
                | ENTRYPOINT
                | FALSE
                | FILESIZE
                | FOR
                | IN
                | INT8
                | INT16
                | INT32
                | INT8BE
                | INT16BE
                | INT32BE
                | MATCHES
                | NOT
                | OR
                | OF
                | THEM
                | TRUE
                | UINT8
                | UINT16
                | UINT32
                | UINT8BE
                | UINT16BE
                | UINT32BE
                | STRINGNAME
                | STRINGNAME_ARRAY
                | STRINGCOUNT
                | REXSTRING'''

        self.parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
        self.parserInterpreter.addElement(ElementTypes.TERM, p[1])

    # Error rule for syntax errors
    def p_error(self, p):
        if p.type in ('COMMENT', 'MCOMMENT'):
             # Just a comment - tell parser that it is okay
             self.parser.errok()
             self.rule_comments.append(p)
        else:
            error_message = "unknown text at {}; token of type {}".format(p.value, p.type)
            rule_success_count = len(self.parserInterpreter.rules)

            self.parser_error['message'] = error_message
            self.parser_error['success_count'] = rule_success_count

            if rule_success_count:
                previous_rule = self.parserInterpreter.rules.pop()
                self.parser_error['last_success'] = previous_rule['rule_name']

            raise TypeError(error_message)

    # Build the parser
    def build(self):
        self.parser = yacc.yacc(module=self, debug=False)

    def run(self, raw_rules):
        # Build parser if not done already
        if not self.parser:
            self.build()

        # Reset parser interpreter state
        self.parserInterpreter.reset()

        # Attempt to parse raw rule content
        self.parser.parse(raw_rules)

        return self.parserInterpreter.rules

import io
import re

import chardet
from plyara import YaraParser, ParserInterpreter
from rest_framework.views import exception_handler

interp = ParserInterpreter()


def check_lexical_convention(entry):
    return interp.is_valid_rule_name(entry)


def generate_kwargs_from_parsed_rule(parsed_rule):
    # Generate parsed rule kwargs for saving a rule
    name = parsed_rule['rule_name']
    tags = parsed_rule.get('tags', [])
    scopes = parsed_rule.get('scopes', [])
    metadata = parsed_rule.get('metadata', {})
    strings = parsed_rule.get('strings', [])
    condition = parsed_rule['condition_terms']
    imports = parsed_rule.get('imports', [])
    comments = parsed_rule.get('comments', [])
    dependencies = interp.detect_rule_dependencies(parsed_rule)

    # Calculate hash value of rule strings and condition
    logic_hash = interp.generate_rule_logic_hash(parsed_rule)

    # Ensure that the proper imports are added based on condition
    detected_imports = interp.detect_rule_imports(parsed_rule)
    imports.extend(detected_imports)

    # TEMP FIX - Use only a single instance of a metakey
    # until YaraGuardian models and functions can be updated
    for key, value in metadata.items():
        if isinstance(value, list):
            metadata[key] = value[0]

    return {'name': name,
            'tags': list(set(tags)),
            'scopes': list(set(scopes)),
            'imports': list(set(imports)),
            'comments': list(set(comments)),
            'metadata': metadata,
            'strings': strings,
            'condition': condition,
            'dependencies': dependencies,
            'logic_hash': logic_hash}


def parse_rule_submission(raw_submission):
    # Instantiate Parser
    parser = YaraParser()

    # Container for results
    submission_results = {'parsed_rules': [],
                          'parser_error': {}}

    try:
        # Check if submission needs to be read and decoded
        if hasattr(raw_submission, 'read'):
            raw_content = raw_submission.read()
            # Attempt to automatically detect encoding
            encoding = chardet.detect(raw_content)['encoding']
            yara_content = raw_content.decode(encoding=encoding)
        else:
            yara_content = raw_submission

    except Exception:
        # Unable to decode or read the submitted content
        yara_content = None
        submission_results['parser_error']['message'] = "Unable to read submission content"

    # Ensure content is not blank before passing to parser
    if yara_content:
        try:
            submission_results['parsed_rules'] = parser.run(yara_content)
        except TypeError:
            submission_results['parser_error'] = parser.parser_error
        except Exception as unexpected_exception:
            submission_results['parser_error'] = unexpected_exception

    # {'message': <error>
    #  'success_count': <count rules parsed>,
    #  'last_success': <last rule parsed name>}

    return submission_results


def build_yarafile(queryset):
    rules = queryset.order_by('dependencies')

    # Temporary rule file container
    temp_file = io.StringIO()

    # Build import search patterns
    import_options = interp.import_options
    import_pattern = 'import \"(?:{})\"\n'.format('|'.join(import_options))

    for rule in rules.iterator():
        # name, tags, imports, metadata, strings, condition, scopes
        formatted_rule = rule.format_rule()
        temp_file.write(formatted_rule)
        temp_file.write('\n\n')

    present_imports = set(re.findall(import_pattern, temp_file.getvalue()))
    importless_file = re.sub(import_pattern, '', temp_file.getvalue())

    # Finalized rule file container
    rule_file = io.StringIO()

    for import_value in present_imports:
        rule_file.write(import_value)

    rule_file.write('\n\n')
    rule_file.write(importless_file)

    return rule_file


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    response.data = {'errors': exc.detail}
    return response

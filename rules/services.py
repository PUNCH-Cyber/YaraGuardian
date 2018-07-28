import io
import re

import chardet
from plyara import Plyara
from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException


def check_lexical_convention(entry):
    return Plyara.is_valid_rule_name(entry)


def generate_kwargs_from_parsed_rule(parsed_rule):
    # Generate parsed rule kwargs for saving a rule
    name = parsed_rule['rule_name']
    tags = parsed_rule.get('tags', [])
    scopes = parsed_rule.get('scopes', [])

    # TODO : Update when Plyara moves to clean Python types
    metadata = parsed_rule.get('metadata', {})
    for key, value in metadata.items():
        if value not in ('true', 'false'):
            try:
                value = int(value)
            except ValueError:
                metadata[key] = '"' + value + '"'

    strings = parsed_rule.get('strings', [])
    condition = parsed_rule['condition_terms']

    # TODO : Update when Plyara moves to stripping quotes from detect_imports module
    imports = [imp.strip('"') for imp in Plyara.detect_imports(parsed_rule)]
    comments = parsed_rule.get('comments', [])
    dependencies = Plyara.detect_dependencies(parsed_rule)

    # Calculate hash value of rule strings and condition
    logic_hash = Plyara.generate_logic_hash(parsed_rule)

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
    parser = Plyara()

    # Container for results
    submission_results = {'parsed_rules': [],
                          'parser_error': ''}

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
        submission_results['parser_error'] = "Unable to read submission content"

    # Ensure content is not blank before passing to parser
    if yara_content:
        try:
            submission_results['parsed_rules'] = parser.parse_string(yara_content)
        except Exception as error:
            submission_results['parser_error'] = str(error)

    return submission_results


def build_yarafile(queryset):
    rules = queryset.order_by('dependencies')

    # Temporary rule file container
    temp_file = io.StringIO()

    # Build import search patterns
    import_options = Plyara.IMPORT_OPTIONS
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
    response_content = {}
    response = exception_handler(exc, context)

    if response is not None:
        response_content['status_code'] = response.status_code
        if 'detail' not in response.data:
            response_content['errors'] = response.data
        else:
            response_content['errors'] = [response.data['detail']]
        response.data = response_content
    return response

from django.http import Http404
from django.conf import settings
from django.db import IntegrityError
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

import re
import datetime

import chardet

from plyara import YaraParser
from plyara import ParserInterpreter

interp = ParserInterpreter()


def get_group_or_404(group_name):
    try:
        group_object = Group.objects.get(name=group_name)
    except ObjectDoesNotExist:
        raise Http404('Non-existent Group')
    else:
        return group_object


def delimit_filtervalue(value):
    delimited_values = re.split('; |, |;|,', value)
    return delimited_values


def check_registration_enabled():
    if settings.GUEST_REGISTRATION in ("PUBLIC", "INVITE"):
        return settings.GUEST_REGISTRATION
    return False


def get_admin_account():
    # Non-login system account for posting auto-generated content
    User = get_user_model()

    try:
        YaraAdmin = User.objects.get(username="YaraAdmin")
    except:
        random_password = User.objects.make_random_password(length=128)

        YaraAdmin = User()
        YaraAdmin.username = "YaraAdmin"
        YaraAdmin.is_active = False
        YaraAdmin.is_staff = True
        YaraAdmin.set_password(random_password)
        YaraAdmin.save()

    return YaraAdmin


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 1000

    def get_paginated_response(self, data):
        # Populate non-page-related query params for reference
        query_params = {}

        for key, value in self.request.query_params.items():
            if key != 'page':
                query_params[key] = value

        # Remove page parameter references from absolute URI for base search reference
        base_search = re.sub(r'(\?|&)page=\d+', '', self.request.build_absolute_uri())
        current_page = self.request.query_params.get(self.page_query_param, 1)

        paginated_response = {'result_count': self.page.paginator.count,
                              'page_count': self.page.paginator.num_pages,
                              'current_page': current_page,
                              'query_params': query_params,
                              'base_search':  base_search,
                              'next': self.get_next_link(),
                              'previous': self.get_previous_link(),
                              'results': data}

        return Response(paginated_response)


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
        submission_results['parser_error']['message'] = "Unable to read submission content"

    # Ensure content is not blank before passing to parser
    if yara_content:
        try:
            submission_results['parsed_rules'] = parser.run(yara_content)
        except TypeError:
            submission_results['parser_error'] = parser.parser_error
        except Exception as unexpected_exception:
            submission_results['parser_error'] = unexpected_exception

            # parser.parser_error = {'message': <error>
            #                        'success_count': <count rules parsed>,
            #                        'last_success': <last rule parsed name>}

    return submission_results


def check_lexical_convention(entry):
    return interp.isValidRuleName(entry)


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
    dependencies = interp.detectDependencies(parsed_rule)

    # Calculate hash value of rule strings and condition
    logic_hash = interp.generateLogicHash(parsed_rule)

    # Ensure that the proper imports are added based on condition
    detected_imports = interp.detectImports(parsed_rule)
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


def process_extracted_comments(rule, comments):
    # TO-DO: Figure out scoping issues so this can be imported just once
    from rules.models import YaraRuleComment

    # Generate comments from parsed comment data
    for comment in comments:
        comment_data = {'created': datetime.datetime.now(),
                        'modified': datetime.datetime.now(),
                        'poster': get_admin_account(),
                        'content': comment, 'rule': rule}

        YaraRuleComment.objects.create(**comment_data)

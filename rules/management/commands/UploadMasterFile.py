import os
import re
import logging

from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from rules.models import YaraRule
from rules.services import parse_rule_submission

User = get_user_model()

# Configure Logging
logging.basicConfig(level=logging.INFO)


class Command(BaseCommand):
    help = 'Ingest yara rules based on specified Yara import file'

    def add_arguments(self, parser):

        # Positional argument
        parser.add_argument('rule_masters', nargs='+')

        # Additional required arguments
        parser.add_argument('--user', required=True)
        parser.add_argument('--group', required=True)

        # Optional arguments
        parser.add_argument('--source',
                            default='')

        parser.add_argument('--category',
                            default='')

    def handle(self, *args, **options):

        username = options['user']
        groupname = options['group']
        rules_source = options['source']
        rules_category = options['category']

        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            user = None
            logging.error('[!] Specified user does not exist')

        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist:
            group = None
            logging.error('[!] Specified group does not exist')

        if user and group:
            for yara_master in options['rule_masters']:

                if os.path.isfile(yara_master):

                    # Change working directory to account for relative imports
                    os.chdir(os.path.dirname(os.path.abspath(yara_master)))

                    with open(yara_master, 'r') as file_object:
                        master_file_contents = file_object.read()

                    include_pattern = r'\ninclude \"([^\"]+)\"'
                    import_files = re.findall(include_pattern, master_file_contents)

                    for file_path in import_files:
                        with open(file_path, 'rb') as raw_content:
                            content_results = parse_rule_submission(raw_content)

                        # Inspect the results from content submission
                        parsed_rules = content_results['parsed_rules']
                        parsing_error = content_results['parser_error']

                        # Identify any parsing errors that occur
                        if parsing_error:
                            message = '[!] Parsing Error: {}'.format(parsing_error)
                            logging.error(message)
                        else:
                            # Save successfully parsed rules
                            save_results = YaraRule.objects.process_parsed_rules(parsed_rules,
                                                                                 rules_source,
                                                                                 rules_category,
                                                                                 user, group,
                                                                                 status=YaraRule.ACTIVE_STATUS)
                            upload_count = save_results['rule_upload_count']
                            collision_count = save_results['rule_collision_count']
                            message = '[✓] Successfully uploaded {} rules and prevented {} rule collisions from {}'.format(upload_count, collision_count, file_path)
                            logging.info(message)

                            for error in save_results['errors']:
                                logging.error(error)

                            for warning in save_results['warnings']:
                                logging.warn(warning)

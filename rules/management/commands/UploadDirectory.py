import os
import logging

from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from unipath import Path

from rules.models import YaraRule
from rules.services import parse_rule_submission

try:
    # Use the built-in version of scandir/walk (3.5+), otherwise
    from os import scandir, walk
except ImportError:
    # use the scandir module version
    from scandir import scandir, walk

User = get_user_model()
logging.basicConfig(level=logging.INFO)


class Command(BaseCommand):

    help = 'Recursively ingest yara rule files from a specified directory'

    def add_arguments(self, parser):

        # Positional argument
        parser.add_argument('rule_directories', nargs='+')

        # Additional required arguments
        parser.add_argument('--user', required=True)

        parser.add_argument('--group', required=True)

        # Optional arguments
        parser.add_argument('--source',
                            default='')

        parser.add_argument('--category',
                            default='')

        parser.add_argument('--folder_as',
                            required=False,
                            choices=['source', 'category'])

    def handle(self, *args, **options):

        username = options['user']
        groupname = options['group']
        rules_source = options['source']
        rules_category = options['category']
        folder_override = options['folder_as']

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
            for yara_directory in options['rule_directories']:
                # Scan an entire directory recursively
                if os.path.isdir(yara_directory):
                    for root_path, subdirs, files in walk(yara_directory):
                        for entry in files:
                            if entry.endswith('.yar') or entry.endswith('.yara'):
                                file_path = os.path.join(root_path, entry)

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
                                    if folder_override == 'source':
                                        rules_source = str(Path(file_path).parent.name)
                                        save_results = YaraRule.objects.process_parsed_rules(parsed_rules,
                                                                                            rules_source,
                                                                                            rules_category,
                                                                                            user, group,
                                                                                            status=YaraRule.ACTIVE_STATUS,
                                                                                            force_source=True)
                                    elif folder_override == 'category':
                                        rules_category = str(Path(file_path).parent.name)
                                        save_results = YaraRule.objects.process_parsed_rules(parsed_rules,
                                                                                            rules_source,
                                                                                            rules_category,
                                                                                            user, group,
                                                                                            status=YaraRule.ACTIVE_STATUS,
                                                                                            force_category=True)
                                    else:
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

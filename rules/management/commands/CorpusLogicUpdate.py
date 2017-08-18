import logging
from django.core.management.base import BaseCommand, CommandError

from plyara import YaraParser
from rules.models import YaraRule

# Configure Logging
logging.basicConfig(level=logging.INFO)


class Command(BaseCommand):

    help = 'Recalculate the logic hashes of the entire rule corpus'

    def handle(self, *args, **options):
        corpus = YaraRule.objects.all()
        rule_count = corpus.count()
        message = 'Updating logic hashes for {} rules'.format(rule_count)
        logging.info(message)
        rule_index = 0

        for rule in corpus.iterator():
            rule_index += 1
            logic_data = {'strings': rule.strings, 'condition_terms': rule.condition}
            logic_hash = YaraParser.parserInterpreter.generateLogicHash(logic_data)
            rule.logic_hash = logic_hash
            rule.save()
            logging.info('Rule Logic Update: {} of {}'.format(rule_index, rule_count))

from django.test import TestCase

from .testing_core import generate_test_user
from .REST_serializers import YaraRuleSerializer


class YaraRuleSerializerTestCase(TestCase):
    # TO-DO

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

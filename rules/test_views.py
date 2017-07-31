from rest_framework.test import APIRequestFactory, force_authenticate

from django.test import TestCase
from django.core.urlresolvers import reverse

from .testing_core import generate_test_user


class RuleViewSetTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.factory = APIRequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

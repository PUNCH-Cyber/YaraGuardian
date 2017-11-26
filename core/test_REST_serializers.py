from django.test import TestCase

from .testing_core import generate_test_user

from .REST_serializers import (PublicGroupSerializer,
                               PublicUserSerializer,
                               PrivateGroupSerializer,
                               GroupMetaUpdateSerializer,
                               PrivateUserSerializer)


class PublicGroupSerializerTestCase(TestCase):
    # TO-DO

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class PrivateGroupSerializerTestCase(TestCase):
    # TO-DO
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupMetaUpdateSerializerTestCase(TestCase):
    # TO-DO
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class PublicUserSerializerTestCase(TestCase):
    # TO-DO
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class PrivateUserSerializerTestCase(TestCase):
    # TO-DO
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

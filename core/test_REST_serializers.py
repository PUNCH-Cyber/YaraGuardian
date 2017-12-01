from django.test import TestCase

from .testing_core import generate_test_user

from .REST_serializers import (PublicGroupSerializer,
                               PublicUserSerializer,
                               PrivateGroupSerializer,
                               GroupMetaUpdateSerializer,
                               PrivateUserSerializer)

from rules.models import YaraRule


class PublicGroupSerializerTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()
        cls.serializer = PublicGroupSerializer(instance=cls.group)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['name',
                                            'owner',
                                            'rule_count',
                                            'member_count'])


class PrivateGroupSerializerTestCase(TestCase):
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()
        cls.serializer = PrivateGroupSerializer(instance=cls.group)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['name',
                                            'owner',
                                            'members',
                                            'source_required',
                                            'source_options',
                                            'category_required',
                                            'category_options',
                                            'nonprivileged_submission_status',
                                            'rule_count'])


class GroupMetaUpdateSerializerTestCase(TestCase):

    def setUp(self):
        self.user = generate_test_user()
        self.group = self.user.groups.get()

    def test_valid_update_source_required(self):
        self.assertTrue(self.group.groupmeta.source_required)
        serializer = GroupMetaUpdateSerializer(self.group.groupmeta,
                                               data={'source_required': False},
                                               partial=True)
        if serializer.is_valid():
            serializer.save()

        self.assertFalse(self.group.groupmeta.source_required)

    def test_valid_update_category_required(self):
        self.assertTrue(self.group.groupmeta.category_required)
        serializer = GroupMetaUpdateSerializer(self.group.groupmeta,
                                               data={'category_required': False},
                                               partial=True)
        if serializer.is_valid():
            serializer.save()

        self.assertFalse(self.group.groupmeta.category_required)

    def test_valid_update_nonprivileged_submission_status(self):
        self.assertEqual(self.group.groupmeta.nonprivileged_submission_status, YaraRule.PENDING_STATUS)
        serializer = GroupMetaUpdateSerializer(self.group.groupmeta,
                                               data={'nonprivileged_submission_status': YaraRule.ACTIVE_STATUS},
                                               partial=True)

        if serializer.is_valid():
            serializer.save()

        self.assertEqual(self.group.groupmeta.nonprivileged_submission_status, YaraRule.ACTIVE_STATUS)


class PublicUserSerializerTestCase(TestCase):
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()
        cls.serializer = PublicUserSerializer(instance=cls.user)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['username'])


class PrivateUserSerializerTestCase(TestCase):
    
    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()
        cls.serializer = PrivateUserSerializer(instance=cls.user)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['email',
                                            'username',
                                            'groups',
                                            'api_token'])

import datetime

from django.test import TestCase

from .models import YaraRule, YaraRuleComment
from .testing_core import generate_test_user
from .REST_serializers import (YaraRuleSerializer,
                               YaraRuleStatsSerializer, 
                               YaraRuleCommentSerializer)


class YaraRuleSerializerTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

        cls.rule = YaraRule.objects.create(name='SerializedRule',
                                           strings={},
                                           condition=[],
                                           tags=['Serialized'],
                                           scopes=['private'],
                                           imports=['\"pe\"'],
                                           metadata={'test': '\"serialization\"'},
                                           dependencies=['Serialization'],
                                           logic_hash='SERIAL' * 6 + '0001',
                                           owner=cls.group,
                                           submitter=cls.user,
                                           source='Serializer Source',
                                           category='Serializer Category',
                                           status=YaraRule.ACTIVE_STATUS)

        cls.serializer = YaraRuleSerializer(instance=cls.rule)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['id',
                                            'name',
                                            'source',
                                            'category',
                                            'status',
                                            'tags',
                                            'imports',
                                            'scopes',
                                            'metadata',
                                            'dependencies',
                                            'formatted_rule',
                                            'submitter',
                                            'comments',
                                            'created',
                                            'modified'])


class YaraRuleStatsSerializerTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

        cls.serializer = YaraRuleStatsSerializer(YaraRule.objects.filter(owner=cls.group),
                                                 context={'group_context': cls.group})

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['source_options',
                                            'category_options',
                                            'tag_list',
                                            'category_list',
                                            'metakey_list',
                                            'source_list',
                                            'import_list',
                                            'scope_list',
                                            'submitter_list',
                                            'tag_count',
                                            'metakey_count',
                                            'source_count',
                                            'category_count',
                                            'active_count',
                                            'inactive_count',
                                            'pending_count',
                                            'rejected_count',
                                            'name_conflict_count',
                                            'logic_collision_count',
                                            'missing_dependency_count'])


class YaraRuleCommentSerializerTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

        cls.rule = YaraRule.objects.create(name='SerializedRule',
                                           strings={},
                                           condition=[],
                                           tags=[],
                                           scopes=[],
                                           imports=[],
                                           metadata={},
                                           dependencies=[],
                                           logic_hash='',
                                           owner=cls.group,
                                           submitter=cls.user,
                                           source='',
                                           category='',
                                           status=YaraRule.ACTIVE_STATUS)

        cls.comment = YaraRuleComment(content='',
                                      poster=cls.user,
                                      rule=cls.rule,
                                      modified=datetime.datetime.now(),
                                      created=datetime.datetime.now())

        cls.serializer = YaraRuleCommentSerializer(instance=cls.comment)

    def test_expected_fields(self):
        data = self.serializer.data
        self.assertCountEqual(data.keys(), ['id',
                                            'content',
                                            'poster',
                                            'modified',
                                            'created'])

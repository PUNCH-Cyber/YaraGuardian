from django.test import TestCase

from .models import YaraRule
from .REST_filters import YaraRuleFilter
from .testing_core import generate_test_user


class YaraRuleFilterTestCase(TestCase):
    """ Test custom filter methods within YaraRuleFilter """

    # Reserved keyword value that should never match
    failure_keyword = 'INVALID'

    @classmethod
    def setUpTestData(cls):
        # Set up data for the whole TestCase
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

        YaraRule.objects.create(name='TestRule1',
                                strings={},
                                condition=[],
                                tags=['Tag1', 'Tag2'],
                                scopes=['private'],
                                imports=['pe'],
                                metadata={'author': '\"Johnny Test\"'},
                                dependencies=[],
                                logic_hash='',
                                owner=cls.group,
                                submitter=cls.user,
                                source='Internal Source',
                                category='Test Rules',
                                status=YaraRule.ACTIVE_STATUS)

        YaraRule.objects.create(name='TestRule2',
                                strings={},
                                condition=[],
                                tags=['Tag1', 'Tag3', 'Tagged'],
                                scopes=['private', 'global'],
                                imports=['pe', 'math'],
                                metadata={'author': '\"John Test\"',
                                          'description': '\"Incredible Rule\"'},
                                dependencies=[],
                                logic_hash='',
                                owner=cls.group,
                                submitter=cls.user,
                                source='Internal Source',
                                category='Test Rules',
                                status=YaraRule.INACTIVE_STATUS)

        YaraRule.objects.create(name='TestRule3',
                                strings={},
                                condition=[],
                                tags=[],
                                scopes=[],
                                imports=[],
                                metadata={},
                                dependencies=['TestRule1', 'TestRule2'],
                                logic_hash='',
                                owner=cls.group,
                                submitter=cls.user,
                                source='External Submission',
                                category='Experimental Rules',
                                status=YaraRule.PENDING_STATUS)

        cls.queryset = YaraRule.objects.all()

    def test_tagged_filter_as_true(self):
        queryset = YaraRuleFilter({'tagged': 'true'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_tagged_filter_as_false(self):
        queryset = YaraRuleFilter({'tagged': 'false'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_any_tag_filter_with_single_tag(self):
        queryset = YaraRuleFilter({'any_tag': 'Tag1'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_tag_filter_with_multiple_tags(self):
        queryset = YaraRuleFilter({'any_tag': 'Tag2, Tag3'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_tag_filter_with_invalid_tag(self):
        queryset = YaraRuleFilter({'any_tag': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_all_tags_filter_with_single_tag(self):
        queryset = YaraRuleFilter({'all_tags': 'Tag1'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_all_tags_filter_with_multiple_tags(self):
        queryset = YaraRuleFilter({'all_tags': 'Tag1, Tag3'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_tags_filter_with_invalid_tag(self):
        queryset = YaraRuleFilter({'all_tags': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_without_tag_filter_with_single_tag(self):
        queryset = YaraRuleFilter({'without_tag': 'Tag1'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_without_tag_filter_with_multiple_tags(self):
        queryset = YaraRuleFilter({'without_tag': 'Tagged, UnknownTag'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_without_tag_filter_with_invalid_tag(self):
        queryset = YaraRuleFilter({'without_tag': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_any_import_filter_with_single_import(self):
        queryset = YaraRuleFilter({'any_import': 'pe'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_import_filter_with_multiple_imports(self):
        queryset = YaraRuleFilter({'any_import': 'pe, math'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_import_filter_with_invalid_import(self):
        queryset = YaraRuleFilter({'any_import': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_all_imports_filter_with_single_import(self):
        queryset = YaraRuleFilter({'all_imports': 'pe'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_all_imports_filter_with_multiple_imports(self):
        queryset = YaraRuleFilter({'all_imports': 'pe, math'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_imports_filter_with_invalid_import(self):
        queryset = YaraRuleFilter({'all_imports': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_any_scope_filter_with_single_scope(self):
        queryset = YaraRuleFilter({'any_scope': 'private'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_scope_filter_with_multiple_scopes(self):
        queryset = YaraRuleFilter({'any_scope': 'private, global'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_scope_filter_with_invalid_scope(self):
        queryset = YaraRuleFilter({'any_scope': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_all_scopes_filter_with_single_scope(self):
        queryset = YaraRuleFilter({'all_scopes': 'private'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_all_scopes_filter_with_multiple_scopes(self):
        queryset = YaraRuleFilter({'all_scopes': 'private, global'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_scopes_filter_with_invalid_scope(self):
        queryset = YaraRuleFilter({'all_scopes': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_any_metakey_filter_with_single_metakey(self):
        queryset = YaraRuleFilter({'any_metakey': 'author'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_metakey_filter_with_multiple_metakeys(self):
        queryset = YaraRuleFilter({'any_metakey': 'author, description'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_any_metakey_filter_with_invalid_metakey(self):
        queryset = YaraRuleFilter({'any_metakey': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_all_metakeys_filter_with_single_metakey(self):
        queryset = YaraRuleFilter({'all_metakeys': 'author'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_all_metakeys_filter_with_multiple_metakeys(self):
        queryset = YaraRuleFilter({'all_metakeys': 'author, description'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_metakeys_filter_with_invalid_metakey(self):
        queryset = YaraRuleFilter({'all_metakeys': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_any_dependency_filter_with_single_dependency(self):
        queryset = YaraRuleFilter({'any_dependency': 'TestRule1'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_any_dependency_filter_with_multiple_dependencies(self):
        queryset = YaraRuleFilter({'any_dependency': 'TestRule1, TestRule3'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_any_dependency_filter_with_invalid_dependency(self):
        queryset = YaraRuleFilter({'any_dependency': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_all_dependencies_filter_with_single_dependency(self):
        queryset = YaraRuleFilter({'all_dependencies': 'TestRule1'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_dependencies_filter_with_multiple_dependencies(self):
        queryset = YaraRuleFilter({'all_dependencies': 'TestRule1, TestRule2'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_all_dependencies_filter_with_invalid_dependency(self):
        queryset = YaraRuleFilter({'all_dependencies': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_identifier_filter_with_single_identifier(self):
        queryset = YaraRuleFilter({'identifier': '1'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_identifier_filter_with_multiple_identifiers(self):
        queryset = YaraRuleFilter({'identifier': '1,2,3'}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_identifier_filter_with_invalid_identifier(self):
        queryset = YaraRuleFilter({'identifier': '5'}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_identifier_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'identifier': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count(), 'Identifier Check with Invalid Param')

    def test_metavalue_contains_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metavalue_contains': 'Test'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_metavalue_contains_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metavalue_contains': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_metavalue_startswith_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metavalue_startswith': 'John'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_metavalue_startswith_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metavalue_startswith': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_metavalue_endswith_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metavalue_endswith': 'Rule'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_metavalue_endswith_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metavalue_endswith': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_metakey_contains_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metakey_contains': 'desc'}, queryset=self.queryset).qs
        self.assertEqual(1, queryset.count())

    def test_metakey_contains_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metakey_contains': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_metakey_startswith_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metakey_startswith': 'auth'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_metakey_startswith_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metakey_startswith': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_metakey_endswith_filter_with_valid_param(self):
        queryset = YaraRuleFilter({'metakey_endswith': 'or'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_metakey_endswith_filter_with_invalid_param(self):
        queryset = YaraRuleFilter({'metakey_endswith': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_submitter_filter_with_single_ID_param(self):
        queryset = YaraRuleFilter({'submitter': '{}'.format(self.user.id)}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_submitter_filter_with_invalid_ID_param(self):
        queryset = YaraRuleFilter({'submitter': '9999'}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_submitter_filter_with_single_username_param(self):
        queryset = YaraRuleFilter({'submitter': '{}'.format(self.user.username)}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_submitter_filter_with_invalid_username_param(self):
        queryset = YaraRuleFilter({'submitter': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_source_filter_with_single_source(self):
        queryset = YaraRuleFilter({'source': 'Internal Source'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_source_filter_with_multiple_sources(self):
        queryset = YaraRuleFilter({'source': 'Internal Source, External Submission'}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_source_filter_with_invalid_source(self):
        queryset = YaraRuleFilter({'source': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

    def test_category_filter_with_single_category(self):
        queryset = YaraRuleFilter({'category': 'Test Rules'}, queryset=self.queryset).qs
        self.assertEqual(2, queryset.count())

    def test_category_filter_with_multiple_categories(self):
        queryset = YaraRuleFilter({'category': 'Test Rules, Experimental Rules'}, queryset=self.queryset).qs
        self.assertEqual(3, queryset.count())

    def test_category_filter_with_invalid_category(self):
        queryset = YaraRuleFilter({'category': self.failure_keyword}, queryset=self.queryset).qs
        self.assertEqual(0, queryset.count())

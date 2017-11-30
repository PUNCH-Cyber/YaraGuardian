from urllib.parse import urlencode

from django.test import TestCase
from django.core.urlresolvers import reverse, resolve
from django.contrib.auth.models import Group

from rest_framework.test import APIRequestFactory, force_authenticate

from core.models import GroupMeta

from .models import YaraRule, YaraRuleComment
from .testing_core import generate_test_user

from .REST_views import (RulesetsListingView,
                         RulesetView,
                         RulesetStatsView,
                         RulesetSearchView,
                         RulesetExportView,
                         RulesetBulkEditView,
                         RulesetDeconflictView,
                         RuleDetailsView,
                         RuleTagsView,
                         RuleMetadataView,
                         RuleCommentsView,
                         RuleCommentDetailsView)


class RulesetsListingViewTestCase(TestCase):

    def setUp(self):
        self.url = reverse('rulesets')
        self.factory = APIRequestFactory()
        self.view = RulesetsListingView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()

    def test_authenticated_get_request(self):
        request = self.factory.get(self.url)
        force_authenticate(request, user=self.user)
        response = self.view(request)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_get_request(self):
        request = self.factory.get(self.url)
        response = self.view(request)
        self.assertEqual(response.status_code, 403)


class RulesetViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetView.as_view()
        
        self.user = generate_test_user()
        self.group = self.user.groups.get()

    @classmethod
    def setUpTestData(cls):
        cls.data = {'source': '',
                    'category': '',
                    'rule_content': 'rule dummy { condition: false }',
                    'status': YaraRule.ACTIVE_STATUS}

    def test_valid_authenticated_post_request(self):
        self.group.groupmeta.source_required = False
        self.group.groupmeta.category_required = False
        self.group.groupmeta.save()

        url = reverse('ruleset', kwargs={'group_name': self.group.name})
        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user)
        response = self.view(request, group_name=self.group.name)

        self.assertEqual(response.status_code, 201)

    def test_invalid_authenticated_post_request(self):
        url = reverse('ruleset', kwargs={'group_name': self.group.name})
        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user)
        response = self.view(request, group_name=self.group.name)

        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_post_request(self):
        url = reverse('ruleset', kwargs={'group_name': self.group.name})
        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)

        self.assertEqual(response.status_code, 403)


class RulesetStatsViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetStatsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

    def test_authenticated_get_request(self):
        url = reverse('ruleset-stats', kwargs={'group_name': self.group1.name})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_get_request(self):
        url = reverse('ruleset-stats', kwargs={'group_name': self.group1.name})
        
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name)
        
        self.assertEqual(response.status_code, 403)

    def test_nonmember_get_request(self):
        url = reverse('ruleset-stats', kwargs={'group_name': self.group2.name})
        
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group2.name)
        
        self.assertEqual(response.status_code, 403)


class RulesetSearchViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetSearchView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

    def test_authenticated_get_request(self):
        url = reverse('ruleset-search', kwargs={'group_name': self.group.name})

        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user)
        response = self.view(request, group_name=self.group.name)
        
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_get_request(self):
        url = reverse('ruleset-search', kwargs={'group_name': self.group.name})

        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)
    
        self.assertEqual(response.status_code, 403)


class RulesetExportViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetExportView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

    def test_authenticated_get_request(self):
        url = reverse('ruleset-export', kwargs={'group_name': self.group.name})

        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user)
        response = self.view(request, group_name=self.group.name)

        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_get_request(self):
        url = reverse('ruleset-export', kwargs={'group_name': self.group.name})

        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)
    
        self.assertEqual(response.status_code, 403)


class RulesetBulkEditViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetBulkEditView.as_view()

        for value in range(1, 4):
            rule = YaraRule.objects.create(name='BulkRule{:04x}'.format(value),
                                           strings={},
                                           condition=[],
                                           tags=[],
                                           scopes=[],
                                           imports=[],
                                           metadata={},
                                           dependencies=[],
                                           logic_hash='',
                                           owner=self.group1,
                                           submitter=self.user1,
                                           source='',
                                           category='',
                                           status=YaraRule.ACTIVE_STATUS)
            rule.save()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

        cls.group1.groupmeta.source_options.append('Bulk Updates')
        cls.group1.groupmeta.category_options.append('Testing')
        cls.group1.groupmeta.save()

        cls.data = {'source': 'Bulk Updates',
                    'category': 'Testing',
                    'rule_content': ['rule dummy { condition: false }'],
                    'status': YaraRule.ACTIVE_STATUS}

    def test_admin_post_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['rule_upload_count'], 1)

        rule = YaraRule.objects.get(name='dummy')
        self.assertEqual(rule.status, YaraRule.ACTIVE_STATUS)

    def test_nonadmin_post_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['rule_upload_count'], 1)

        rule = YaraRule.objects.get(name='dummy')
        self.assertEqual(rule.status, self.group1.groupmeta.nonprivileged_submission_status)

    def test_unauthenticated_post_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.post(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)

    def test_valid_admin_patch_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        query_string = urlencode({'name_startswith': 'BulkRule'})
        request = self.factory.patch(url + '?' + query_string, {'add_tags': ['UPDATED']})
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['modified_rule_count'], 3)

    def test_invalid_admin_patch_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url, {'add_tags': ['UPDATED']})
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['modified_rule_count'], 0)

    def test_nonadmin_patch_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_patch_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)

    def test_valid_admin_delete_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        query_string = urlencode({'name_startswith': 'BulkRule'})
        request = self.factory.delete(url + '?' + query_string)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.data['deleted_rule_count'], 3)

    def test_invalid_admin_delete_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.data['deleted_rule_count'], 0)

    def test_nonadmin_delete_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_delete_request(self):
        url = reverse('ruleset-bulk', kwargs={'group_name': self.group1.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)


class RulesetDeconflictViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetDeconflictView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

    def test_admin_patch_request(self):
        url = reverse('ruleset-deconflict', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 200)

    def test_nonadmin_patch_request(self):
        url = reverse('ruleset-deconflict', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_patch_request(self):
        url = reverse('ruleset-deconflict', kwargs={'group_name': self.group1.name})
        request = self.factory.patch(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name)

        self.assertEqual(response.status_code, 403)


class RuleDetailsViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RuleDetailsView.as_view()

        self.rule = YaraRule.objects.create(name='dummy',
                                            strings={},
                                            condition=[],
                                            tags=[],
                                            scopes=[],
                                            imports=[],
                                            metadata={},
                                            dependencies=[],
                                            logic_hash='',
                                            owner=self.group1,
                                            submitter=self.user1,
                                            source='',
                                            category='',
                                            status=YaraRule.ACTIVE_STATUS)

        self.rule.save()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

    def test_member_get_request(self):
        url = reverse('rule-details', kwargs={'group_name': self.group1.name, 'rule_pk': self.rule.id})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['name'], self.rule.name)

    def test_unauthenticated_get_request(self):
        url = reverse('rule-details', kwargs={'group_name': self.group1.name, 'rule_pk': self.rule.id})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 403)
    """
    def test_admin_put_request(self):
        pass

    def test_nonadmin_put_request(self):
        pass

    def test_unauthenticated_put_request(self):
        pass

    def test_admin_patch_request(self):
        pass

    def test_nonadmin_patch_request(self):
        pass

    def test_unauthenticated_patch_request(self):
        pass
    """
    def test_admin_delete_request(self):
        url = reverse('rule-details', kwargs={'group_name': self.group1.name, 'rule_pk': self.rule.id})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 204)
        self.assertFalse(YaraRule.objects.filter(id=self.rule.id).exists())

    def test_nonadmin_delete_request(self):
        url = reverse('rule-details', kwargs={'group_name': self.group1.name, 'rule_pk': self.rule.id})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_delete_request(self):
        url = reverse('rule-details', kwargs={'group_name': self.group1.name, 'rule_pk': self.rule.id})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 403)


class RuleTagsViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RuleTagsView.as_view()

        self.rule = YaraRule.objects.create(name='dummy',
                                            strings={},
                                            condition=[],
                                            tags=['tagged'],
                                            scopes=[],
                                            imports=[],
                                            metadata={},
                                            dependencies=[],
                                            logic_hash='',
                                            owner=self.group1,
                                            submitter=self.user1,
                                            source='',
                                            category='',
                                            status=YaraRule.ACTIVE_STATUS)

        self.rule.save()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

    def test_admin_delete_request(self):
        url = reverse('rule-tags', kwargs={'group_name': self.group1.name, 
                                           'rule_pk': self.rule.id,
                                           'tag': 'tagged'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, tag='tagged')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['tags']), 0)
        self.assertFalse('tagged' in YaraRule.objects.get(id=self.rule.id).tags)

    def test_nonadmin_delete_request(self):
        url = reverse('rule-tags', kwargs={'group_name': self.group1.name, 
                                           'rule_pk': self.rule.id,
                                           'tag': 'tagged'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, tag='tagged')
        
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_delete_request(self):
        url = reverse('rule-tags', kwargs={'group_name': self.group1.name, 
                                           'rule_pk': self.rule.id,
                                           'tag': 'tagged'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, tag='tagged')
        
        self.assertEqual(response.status_code, 403)


class RuleMetadataViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RuleMetadataView.as_view()

        self.rule = YaraRule.objects.create(name='dummy',
                                            strings={},
                                            condition=[],
                                            tags=[],
                                            scopes=[],
                                            imports=[],
                                            metadata={'key': 'value'},
                                            dependencies=[],
                                            logic_hash='',
                                            owner=self.group1,
                                            submitter=self.user1,
                                            source='',
                                            category='',
                                            status=YaraRule.ACTIVE_STATUS)

        self.rule.save()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

    def test_admin_delete_request(self):
        url = reverse('rule-metadata', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id,
                                               'metakey': 'key'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, metakey='key')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['metadata'].keys()), 0)
        self.assertFalse('key' in YaraRule.objects.get(id=self.rule.id).metadata)

    def test_nonadmin_delete_request(self):
        url = reverse('rule-metadata', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id,
                                               'metakey': 'key'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, metakey='key')
        
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_delete_request(self):
        url = reverse('rule-metadata', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id,
                                               'metakey': 'key'})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name,
                             rule_pk=self.rule.id, metakey='key')
        
        self.assertEqual(response.status_code, 403)


class RuleCommentsViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RuleCommentsView.as_view()

        self.rule = YaraRule.objects.create(name='dummy',
                                            strings={},
                                            condition=[],
                                            tags=[],
                                            scopes=[],
                                            imports=[],
                                            metadata={},
                                            dependencies=[],
                                            logic_hash='',
                                            owner=self.group1,
                                            submitter=self.user1,
                                            source='',
                                            category='',
                                            status=YaraRule.ACTIVE_STATUS)
        self.rule.save()

        self.comment = YaraRuleComment.objects.create(content='Comment Data',
                                                      poster=self.user1,
                                                      rule=self.rule)
        self.comment.save()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='VIEW_TESTER_0001')
        cls.user2 = generate_test_user(username='VIEW_TESTER_0002')
        
        cls.group1 = cls.user1.groups.get()
        cls.group2 = cls.user2.groups.get()

        # Add user2 to group1
        cls.user2.groups.add(cls.group1)

    def test_member_get_request(self):
        url = reverse('rule-comments', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['content'], 'Comment Data')

    def test_unauthenticated_get_request(self):
        url = reverse('rule-comments', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 403)

    def test_admin_post_request(self):
        url = reverse('rule-comments', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id})
        request = self.factory.post(url, {'content': 'New Comment'})
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)

        self.assertEqual(response.status_code, 201)
        self.assertTrue(YaraRuleComment.objects.filter(content='New Comment').exists())

    def test_nonadmin_post_request(self):
        url = reverse('rule-comments', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id})
        request = self.factory.post(url, {})
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_post_request(self):
        url = reverse('rule-comments', kwargs={'group_name': self.group1.name, 
                                               'rule_pk': self.rule.id})
        request = self.factory.post(url, {})
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group1.name, rule_pk=self.rule.id)
        
        self.assertEqual(response.status_code, 403)


class RuleCommentDetailsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('rule-comment-details')
        self.factory = APIRequestFactory()
        self.view = RuleCommentDetailsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

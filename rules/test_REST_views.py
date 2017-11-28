from django.test import TestCase
from django.core.urlresolvers import reverse, resolve
from rest_framework.test import APIRequestFactory, force_authenticate

from django.contrib.auth.models import Group

from core.models import GroupMeta

from .models import YaraRule
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
        cls.user = generate_test_user(username='RULE_TESTER_0001')
        cls.group = cls.user.groups.get()

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
        
        self.user1 = generate_test_user(username='RULE_TESTER_0001')
        self.group_meta = self.user1.groups.get().groupmeta

    @classmethod
    def setUpTestData(cls):
        cls.data = {'source': '',
                    'category': '',
                    'rule_content': 'rule dummy { condition: false }',
                    'status': YaraRule.ACTIVE_STATUS}

    def test_valid_authenticated_post_request(self):
        self.group_meta.source_required = False
        self.group_meta.category_required = False
        self.group_meta.save()

        group_name = self.user1.groups.get().name
        url = reverse('ruleset', kwargs={'group_name': group_name})

        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)

        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=group_name)

        self.assertEqual(response.status_code, 201)

    def test_invalid_authenticated_post_request(self):
        group_name = self.user1.groups.get().name
        url = reverse('ruleset', kwargs={'group_name': group_name})

        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)

        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=group_name)

        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_post_request(self):
        group_name = self.user1.groups.get().name
        url = reverse('ruleset', kwargs={'group_name': group_name})

        request = self.factory.post(url, self.data)
        request.resolver_match = resolve(url)

        response = self.view(request, group_name=group_name)

        self.assertEqual(response.status_code, 403)


class RulesetStatsViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RulesetStatsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user1 = generate_test_user(username='RULE_TESTER_0001')
        cls.user2 = generate_test_user(username='RULE_TESTER_0002')

    def test_authenticated_get_request(self):
        group_name = self.user1.groups.get().name
        url = reverse('ruleset-stats', kwargs={'group_name': group_name})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=group_name)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_get_request(self):
        group_name = self.user1.groups.get().name
        url = reverse('ruleset-stats', kwargs={'group_name': group_name})
        
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=group_name)
        
        self.assertEqual(response.status_code, 403)

    def test_nonmember_get_request(self):
        group_name = self.user2.groups.get().name
        url = reverse('ruleset-stats', kwargs={'group_name': group_name})
        
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=group_name)
        
        self.assertEqual(response.status_code, 403)


class RulesetSearchViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-search')
        self.factory = APIRequestFactory()
        self.view = RulesetSearchView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RulesetExportViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-export')
        self.factory = APIRequestFactory()
        self.view = RulesetExportView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RulesetBulkEditViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-bulk')
        self.factory = APIRequestFactory()
        self.view = RulesetBulkEditView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RulesetDeconflictViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-deconflict')
        self.factory = APIRequestFactory()
        self.view = RulesetDeconflictView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RuleDetailsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-details')
        self.factory = APIRequestFactory()
        self.view = RuleDetailsView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RuleTagsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-tags')
        self.factory = APIRequestFactory()
        self.view = RuleTagsView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RuleMetadataViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-metadata')
        self.factory = APIRequestFactory()
        self.view = RuleMetadataView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RuleCommentsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-comments')
        self.factory = APIRequestFactory()
        self.view = RuleCommentsView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RuleCommentDetailsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-comment-details')
        self.factory = APIRequestFactory()
        self.view = RuleCommentDetailsView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

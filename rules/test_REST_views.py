from django.test import TestCase
from django.core.urlresolvers import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

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
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset')
        self.factory = APIRequestFactory()
        self.view = RulesetView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class RulesetStatsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('ruleset-stats')
        self.factory = APIRequestFactory()
        self.view = RulesetStatsView

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


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

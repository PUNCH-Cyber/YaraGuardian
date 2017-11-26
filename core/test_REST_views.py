from django.test import TestCase
from django.core.urlresolvers import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

from .testing_core import generate_test_user

from .REST_views import (AccountView, 
                         AccountGroupsView,
                         GroupsView,
                         GroupDetailsView,
                         GroupMembersView,
                         GroupAdminsView,
                         GroupSourcesView,
                         GroupCategoriesView)


class AccountViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('account')
        self.factory = APIRequestFactory()
        self.view = AccountView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class AccountGroupsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('account-groups')
        self.factory = APIRequestFactory()
        self.view = AccountGroupsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('groups')
        self.factory = APIRequestFactory()
        self.view = GroupsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupDetailsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('group-details')
        self.factory = APIRequestFactory()
        self.view = GroupDetailsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupMembersViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('group-members')
        self.factory = APIRequestFactory()
        self.view = GroupMembersView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupAdminsViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('group-admins')
        self.factory = APIRequestFactory()
        self.view = GroupAdminsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupSourcesViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('group-sources')
        self.factory = APIRequestFactory()
        self.view = GroupSourcesView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()


class GroupCategoriesViewTestCase(TestCase):
    # TO-DO

    def setUp(self):
        self.url = reverse('group-categories')
        self.factory = APIRequestFactory()
        self.view = GroupCategoriesView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

from django.test import TestCase
from django.contrib.auth.models import Group
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

from .REST_serializers import (PrivateGroupSerializer,
                               PublicGroupSerializer,
                               PrivateUserSerializer)


class AccountViewTestCase(TestCase):

    def setUp(self):
        self.url = reverse('account')
        self.factory = APIRequestFactory()
        self.view = AccountView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user(username='VIEW_TESTER_0001')
        cls.group = cls.user.groups.get()

    def test_authenticated_get_request(self):
        request = self.factory.get(self.url)
        force_authenticate(request, user=self.user)
        response = self.view(request)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PrivateUserSerializer(self.user).data)

    def test_unauthenticated_get_request(self):
        request = self.factory.get(self.url)
        response = self.view(request)
        self.assertEqual(response.status_code, 403)


class AccountGroupsViewTestCase(TestCase):

    def setUp(self):
        self.url = reverse('account-groups')
        self.factory = APIRequestFactory()
        self.view = AccountGroupsView.as_view()
        self.user = generate_test_user(username='VIEW_TESTER_0001')
        self.group = self.user.groups.get()

    def test_authenticated_get_request(self):
        request = self.factory.get(self.url)
        force_authenticate(request, user=self.user)
        response = self.view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PrivateGroupSerializer(self.user.groups.all(), many=True).data)

    def test_unauthenticated_get_request(self):
        request = self.factory.get(self.url)
        response = self.view(request)

        self.assertEqual(response.status_code, 403)

    def test_valid_authenticated_post_request(self):
        request = self.factory.post(self.url, {'name': 'NEW_GROUP'})
        force_authenticate(request, user=self.user)
        response = self.view(request)

        self.assertEqual(response.status_code, 201)
        self.assertTrue(self.user.groups.filter(name='NEW_GROUP').exists())

    def test_invalid_authenticated_post_request_blank_name(self):
        request = self.factory.post(self.url, {'name': ''})
        force_authenticate(request, user=self.user)
        response = self.view(request)

        self.assertEqual(response.status_code, 400)

    def test_invalid_authenticated_post_request_already_exists(self):
        request = self.factory.post(self.url, {'name': 'VIEW_TESTER_0001'})
        force_authenticate(request, user=self.user)
        response = self.view(request)

        self.assertEqual(response.status_code, 400)

    def test_invalid_authenticated_post_request_spaces_in_name(self):
        request = self.factory.post(self.url, {'name': 'NEW GROUP'})
        force_authenticate(request, user=self.user)
        response = self.view(request)

        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_post_request(self):
        request = self.factory.post(self.url, {'name': 'NEW_GROUP'})
        response = self.view(request)
        
        self.assertEqual(response.status_code, 403)


class GroupsViewTestCase(TestCase):

    def setUp(self):
        self.url = reverse('groups')
        self.factory = APIRequestFactory()
        self.view = GroupsView.as_view()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

    def test_authenticated_get_request(self):
        request = self.factory.get(self.url)
        force_authenticate(request, user=self.user)
        response = self.view(request)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PublicGroupSerializer(Group.objects.all(), many=True).data)

    def test_unauthenticated_get_request(self):
        request = self.factory.get(self.url)
        response = self.view(request)
        self.assertEqual(response.status_code, 403)


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

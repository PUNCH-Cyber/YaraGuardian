from django.test import TestCase
from django.contrib.auth.models import Group
from django.core.urlresolvers import reverse, resolve
from rest_framework.test import APIRequestFactory, force_authenticate

from .testing_core import generate_test_user

from .models import GroupMeta

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

from rules.models import YaraRule


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

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = GroupDetailsView.as_view()

        self.user1 = generate_test_user(username='VIEW_TESTER_0001')
        self.user2 = generate_test_user(username='VIEW_TESTER_0002')
        self.user3 = generate_test_user(username='VIEW_TESTER_0003')
        
        self.group = Group.objects.create(name='CREATED_GROUP')
        self.group.save()

        group_meta = GroupMeta.objects.create(group=self.group, owner=self.user1)
        group_meta.save()

        self.user1.groups.add(self.group)
        self.user2.groups.add(self.group)
        self.user3.groups.add(self.group)

        self.group.groupmeta.admins.add(self.user2)
        self.group.groupmeta.save()

    def test_authenticated_get_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PrivateGroupSerializer(self.group).data)

    def test_unauthenticated_get_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.get(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PublicGroupSerializer(self.group).data)

    def test_owner_patch_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.patch(url, {'source_required': False,
                                           'category_required': False,
                                           'nonprivileged_submission_status': YaraRule.ACTIVE_STATUS})

        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user1)

        self.assertTrue(self.group.groupmeta.source_required)
        self.assertTrue( self.group.groupmeta.category_required)
        self.assertEqual(self.group.groupmeta.nonprivileged_submission_status, YaraRule.PENDING_STATUS)

        response = self.view(request, group_name=self.group.name)

        self.group.groupmeta.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.group.groupmeta.source_required)
        self.assertFalse( self.group.groupmeta.category_required)
        self.assertEqual(self.group.groupmeta.nonprivileged_submission_status, YaraRule.ACTIVE_STATUS)

    def test_admin_patch_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.patch(url, {})
        request.resolver_match = resolve(url)

        force_authenticate(request, user=self.user2)
        self.assertTrue(self.user2 in self.group.groupmeta.admins.all())

        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)

    def test_member_patch_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.patch(url, {})
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user3)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_patch_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.patch(url, {})
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)

    def test_owner_delete_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)

        force_authenticate(request, user=self.user1)
        self.assertTrue(Group.objects.filter(name=self.group.name).exists())

        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Group.objects.filter(name=self.group.name).exists())

    def test_admin_delete_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user2)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)

    def test_member_delete_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        force_authenticate(request, user=self.user3)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_delete_request(self):
        url = reverse('group-details', kwargs={'group_name': self.group.name})
        request = self.factory.delete(url)
        request.resolver_match = resolve(url)
        response = self.view(request, group_name=self.group.name)
        self.assertEqual(response.status_code, 403)


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

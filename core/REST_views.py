import re
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .services import get_group_or_404

from .REST_permissions import (group_member,
                               IsGroupOwner,
                               IsGroupAdmin,
                               IsGroupAdminOrMemberReadOnly,
                               IsGroupOwnerOrPublicReadOnly)

from .REST_serializers import (PublicGroupSerializer,
                               GroupMetaUpdateSerializer,
                               PrivateUserSerializer,
                               PrivateGroupSerializer)

from .patterns import group_name_pattern

from .models import GroupMeta

User = get_user_model()

group_name_regex = re.compile('^' + group_name_pattern + '$')


class AccountView(RetrieveAPIView):
    """
    List authenticated user details
    """
    permission_classes = [IsAuthenticated]
    serializer_class = PrivateUserSerializer

    def get_object(self):
        return self.request.user


class AccountGroupsView(APIView):
    """
    get:
    List authenticated user groups.

    post:
    Create a new group context.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = PrivateGroupSerializer(request.user.groups.all(), many=True)
        return Response(serializer.data)

    def post(self, request, **kwargs):
        group_name = request.data.get('name', None)

        # Ensure group name was specified
        if not group_name:
            return Response({'errors': ['No Group Name Specified']},
                            status=status.HTTP_400_BAD_REQUEST)

        # Verify group does not already exist
        elif Group.objects.filter(name=group_name).exists():
            return Response({'errors': ['Group Already Exists']},
                            status=status.HTTP_400_BAD_REQUEST)

        # Verify a user with the same name does not already exist
        elif User.objects.filter(username=group_name).exists():
            return Response({'errors': ['Group Already Exists']},
                            status=status.HTTP_400_BAD_REQUEST)

        # Verify group is allowed in URL routing
        elif not group_name_regex.match(group_name):
            return Response({'errors': ['Invalid Group Name']},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create group and group meta
        else:
            group_object = Group.objects.create(name=group_name)
            group_object.save()

            group_meta = GroupMeta.objects.create(group=group_object, owner=request.user)
            group_meta.save()

            request.user.groups.add(group_object)

        return Response(status=status.HTTP_201_CREATED)


class GroupsView(ListAPIView):
    """
    List details on all groups.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = PublicGroupSerializer
    queryset = Group.objects.all()


class GroupDetailsView(APIView):
    """
    get:
    Retrieve details on a specific group.

    put:
    Update group

    delete:
    Delete specified group.
    """
    permission_classes = [IsGroupOwnerOrPublicReadOnly]

    def get(self, request, group_name):
        group_object = get_group_or_404(group_name)

        if group_member(request):
            serializer = PrivateGroupSerializer(group_object)
        else:
            serializer = PublicGroupSerializer(group_object)

        return Response(serializer.data)

    def patch(self, request, group_name):
        group_object = get_group_or_404(group_name)
        serializer = GroupMetaUpdateSerializer(group_object.groupmeta,
                                               data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()

        return Response(serializer.data)

    def delete(self, request, group_name):
        group_object = get_group_or_404(group_name)

        if group_name != request.user.username:
            group_object.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupMembersView(APIView):
    """
    get:
    List group members.

    patch:
    Add new specified group members.

    delete:
    Remove specified members from group.
    """
    permission_classes = [IsGroupOwner]

    def get(self, request, group_name):
        group_object = get_group_or_404(group_name)
        return Response(group_object.user_set.all().values_list('username', flat=True))

    def patch(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_owner_name = group_object.groupmeta.owner.username

        # Gather the submitted member name list
        try:
            new_member_names = request.data.getlist('member')
        except AttributeError:
            new_member_names = request.data.get('member', list())

        if not isinstance(new_member_names, list):
            new_member_names = [new_member_names]

        # Ensure group owner doesn't get inadvertently processed
        if group_owner_name in new_member_names:
            new_member_names = list(set(new_member_names))
            new_member_names.remove(group_owner_name)

        # Gather user objects for processing
        new_members = User.objects.filter(username__in=new_member_names)

        # Add members
        for member in new_members:
            member.groups.add(group_object)

        return Response(group_object.user_set.all().values_list('username', flat=True))

    def delete(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_owner_name = group_object.groupmeta.owner.username

        # Gather user objects for processing
        member_name_list = request.query_params.getlist('member')
        removed_members = User.objects.filter(username__in=member_name_list)

        # Remove from group
        for member in removed_members.exclude(username=group_owner_name):
            group_object.groupmeta.admins.remove(member)
            member.groups.remove(group_object)

        return Response(group_object.user_set.all().values_list('username', flat=True))


class GroupAdminsView(APIView):
    """
    get:
    List group admins.

    patch:
    Add new specified group admins.

    delete:
    Remove specified admins from group.
    """
    permission_classes = [IsGroupOwner]

    def get(self, request, group_name):
        group_object = get_group_or_404(group_name)
        return Response(group_object.groupmeta.admins.all().values_list('username', flat=True))

    def patch(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_owner_name = group_object.groupmeta.owner.username

        # Gather the submitted admin name list
        try:
            new_admin_names = request.data.getlist('admin')
        except AttributeError:
            new_admin_names = request.data.get('admin', list())

        if not isinstance(new_admin_names, list):
            new_admin_names = [new_admin_names]

        # Ensure group owner doesn't get inadvertently processed
        if group_owner_name in new_admin_names:
            new_admin_names = list(set(new_admin_names))
            new_admin_names.remove(group_owner_name)

        # Gather user objects for processing
        new_admin_users = User.objects.filter(username__in=new_admin_names)

        # Add admins
        for admin in new_admin_users:
            admin.groups.add(group_object)
            group_object.groupmeta.admins.add(admin)

        return Response(group_object.groupmeta.admins.all().values_list('username', flat=True))

    def delete(self, request, group_name):
        group_object = get_group_or_404(group_name)
        admin_name_list = request.query_params.getlist('admin')

        # Gather user objects for processing
        removed_admins = User.objects.filter(username__in=admin_name_list)

        # Remove from group
        for admin in removed_admins:
            group_object.groupmeta.admins.remove(admin)

        return Response(group_object.groupmeta.admins.all().values_list('username', flat=True))


class GroupSourcesView(APIView):
    """
    get:
    List group sources.

    patch:
    Add new specified group sources.

    delete:
    Remove specified sources from group.
    """
    permission_classes = [IsGroupAdminOrMemberReadOnly]

    def get(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta
        return Response(group_metadata.source_options)

    def patch(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta

        # Gather the submitted source list
        try:
            new_sources = request.data.getlist('source')
        except AttributeError:
            new_sources = request.data.get('source', list())

        if not isinstance(new_sources, list):
            new_sources = [new_sources]

        for source in new_sources:
            if source not in group_metadata.source_options:
                group_metadata.source_options.append(source)

        group_metadata.save()

        return Response(group_metadata.source_options)

    def delete(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta
        source_list = request.query_params.getlist('source')

        for source in source_list:
            try:
                group_metadata.source_options.remove(source)
            except ValueError:
                pass

        group_metadata.save()

        return Response(group_metadata.source_options)


class GroupCategoriesView(APIView):
    """
    get:
    List group categories.

    patch:
    Add new specified group categories.

    delete:
    Remove specified categories from group.
    """
    permission_classes = [IsGroupAdminOrMemberReadOnly]

    def get(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta
        return Response(group_metadata.category_options)

    def patch(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta

        # Gather the submitted category list
        try:
            new_categories = request.data.getlist('category')
        except AttributeError:
            new_categories = request.data.get('category', list())

        if not isinstance(new_categories, list):
            new_categories = [new_categories]

        for category in new_categories:
            if category not in group_metadata.category_options:
                group_metadata.category_options.append(category)

        group_metadata.save()

        return Response(group_metadata.category_options)

    def delete(self, request, group_name):
        group_object = get_group_or_404(group_name)
        group_metadata = group_object.groupmeta

        category_list = request.query_params.getlist('category')

        for category in category_list:
            try:
                group_metadata.category_options.remove(category)
            except ValueError:
                pass

        group_metadata.save()

        return Response(group_metadata.category_options)

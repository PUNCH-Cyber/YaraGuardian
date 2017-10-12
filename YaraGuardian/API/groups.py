from django.conf.urls import include, url

from core.REST_views import (GroupsView, GroupDetailsView,
                             GroupMembersView, GroupAdminsView,
                             GroupSourcesView, GroupCategoriesView)

from core.patterns import group_name_pattern


urlpatterns = [
    url(r'^$', GroupsView.as_view(),
        name='groups'),

    url(r'^{}/$'.format(group_name_pattern),
        GroupDetailsView.as_view(), name='group-details'),

    url(r'^{}/members/$'.format(group_name_pattern),
        GroupMembersView.as_view(), name='group-members'),

    url(r'^{}/admins/$'.format(group_name_pattern),
        GroupAdminsView.as_view(), name='group-admins'),

    url(r'^{}/sources/$'.format(group_name_pattern),
        GroupSourcesView.as_view(), name='group-sources'),

    url(r'^{}/categories/$'.format(group_name_pattern),
        GroupCategoriesView.as_view(), name='group-categories')
]

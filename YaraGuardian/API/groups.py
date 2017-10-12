from django.conf.urls import include, url

from core.REST_views import (GroupsView, GroupDetailsView,
                             GroupMembersView, GroupAdminsView,
                             GroupSourcesView, GroupCategoriesView)

urlpatterns = [
    url(r'^$', GroupsView.as_view(), name='groups'),
    url(r'^(?P<group_name>[\s\w]+)/$', GroupDetailsView.as_view(), name='group-details'),
    url(r'^(?P<group_name>[\s\w]+)/members/$', GroupMembersView.as_view(), name='group-members'),
    url(r'^(?P<group_name>[\s\w]+)/admins/$', GroupAdminsView.as_view(), name='group-admins'),
    url(r'^(?P<group_name>[\s\w]+)/sources/$', GroupSourcesView.as_view(), name='group-sources'),
    url(r'^(?P<group_name>[\s\w]+)/categories/$', GroupCategoriesView.as_view(), name='group-categories')
]

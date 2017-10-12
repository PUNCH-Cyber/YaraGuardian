from django.conf.urls import include, url

from core.REST_views import (AccountView, AccountGroupsView)

urlpatterns = [
    url(r'^$', AccountView.as_view(),
        name='account'),

    url(r'^groups/$', AccountGroupsView.as_view(),
        name='account-groups'),
]

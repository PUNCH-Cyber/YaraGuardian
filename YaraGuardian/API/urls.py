from django.conf.urls import include, url

from rest_framework.authtoken import views

import YaraGuardian.API.account
import YaraGuardian.API.groups
import YaraGuardian.API.rules


urlpatterns = [
    # url(r'^', include('rest_framework_docs.urls')), 
    url(r'^token-auth/', views.obtain_auth_token),
    url(r'^account/', include(YaraGuardian.API.account)),
    url(r'^groups/', include(YaraGuardian.API.groups)),
    url(r'^rules/', include(YaraGuardian.API.rules)),
]

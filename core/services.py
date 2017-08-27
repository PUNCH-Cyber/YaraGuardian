import re

from django.http import Http404
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist


def get_group_or_404(group_name):
    try:
        group_object = Group.objects.get(name=group_name)
    except ObjectDoesNotExist:
        raise Http404('Non-existent Group')
    else:
        return group_object


def delimit_filtervalue(value):
    delimited_values = re.split('; |, |;|,', value)
    return delimited_values


def check_registration_enabled():
    if settings.GUEST_REGISTRATION in ("PUBLIC", "INVITE"):
        return settings.GUEST_REGISTRATION
    return False


def get_admin_account():
    # Non-login system account for posting auto-generated content
    User = get_user_model()

    try:
        YaraAdmin = User.objects.get(username="YaraAdmin")
    except:
        random_password = User.objects.make_random_password(length=128)

        YaraAdmin = User()
        YaraAdmin.username = "YaraAdmin"
        YaraAdmin.is_active = False
        YaraAdmin.is_staff = True
        YaraAdmin.set_password(random_password)
        YaraAdmin.save()

    return YaraAdmin
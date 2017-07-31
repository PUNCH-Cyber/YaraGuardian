import logging
import datetime

from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from .models import GroupMeta

User = get_user_model()
logger = logging.getLogger('YaraGuardian.core.signals')


@receiver(post_save, sender=User, dispatch_uid="create_initial_token")
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=User, dispatch_uid="create_initial_group")
def create_initial_group(sender, instance, created=False, **kwargs):

    if created:
        group_object = Group.objects.create(name=instance.username)
        group_object.save()

        group_meta = GroupMeta.objects.create(group=group_object, owner=instance)
        group_meta.save()

        instance.groups.add(group_object)


@receiver(user_logged_in)
def log_session(sender, user, request, **kwargs):
    if request:
        user = request.user.username
        timestamp = datetime.datetime.now()

        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')

        if x_forwarded:
            ip_addr = x_forwarded.split(',')[0]
        else:
            ip_addr = request.META.get('REMOTE_ADDR')

        msg = 'User {} logged in from IP {} at {}'.format(user, ip_addr, timestamp)
        logger.info(msg)

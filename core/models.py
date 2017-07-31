import os
import hashlib
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.models import AbstractUser, Group
from django.contrib.postgres.fields import ArrayField
from django.template.loader import get_template


class TimeStampedModel(models.Model):
    modified = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        abstract = True


class User(AbstractUser):

    def save(self, *args, **kwargs):
        # Ensure new user name does not conflict with already existing group
        if self._state.adding == True:
            if Group.objects.filter(name=self.username).count():
                raise ValidationError('Username already taken')

        super(User, self).save(*args, **kwargs)


class GroupMeta(models.Model):
    group = models.OneToOneField(Group, on_delete=models.CASCADE, primary_key=True)
    owner = models.ForeignKey(User, related_name="group_owner")
    admins = models.ManyToManyField(User)

    source_required = models.BooleanField(default=True)
    source_options = ArrayField(models.CharField(max_length=75), default=list)

    category_required = models.BooleanField(default=True)
    category_options = ArrayField(models.CharField(max_length=75), default=list)

    def save(self, *args, **kwargs):
        self.source_options = list(set(self.source_options))
        self.category_options = list(set(self.category_options))

        super(GroupMeta, self).save(*args, **kwargs)


class RegistrationToken(TimeStampedModel):

    def generate_token():
        return hashlib.sha256(os.urandom(4096)).hexdigest()

    email = models.EmailField(unique=True)
    token = models.CharField(max_length=64, default=generate_token)

    def save(self, *args, **kwargs):
        subject = 'Registration'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [self.email]

        # Grab templates
        plaintext_template = get_template('emails/RegistrationEmail.txt')
        html_template = get_template('emails/RegistrationEmail.html')

        # Specify context data
        template_context = {'token': self.token,
                            'email': self.email}

        # Render templates with context data
        text_message = plaintext_template.render(template_context)
        html_message = html_template.render(template_context)

        message = EmailMultiAlternatives(subject,
                                         text_message,
                                         from_email,
                                         recipient_list)

        message.attach_alternative(html_message, "text/html")
        message.send()

        super(RegistrationToken, self).save(*args, **kwargs)

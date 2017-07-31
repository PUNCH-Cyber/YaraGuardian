from django import forms
from core.services import check_registration_enabled
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group

from core.models import RegistrationToken

User = get_user_model()


class RegistrationForm(forms.Form):

    username = forms.CharField(required=True,
                               label='Username',
                               widget=forms.TextInput())

    email = forms.EmailField(required=True,
                             label='Email Address',
                             widget=forms.TextInput())

    token = forms.CharField(required=False,
                            disabled=True,
                            label='Registration Token',
                            widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)

        # Require a token if registration is invite only
        if check_registration_enabled() == 'INVITE':
            self.fields['token'].disabled = False
            self.fields['token'].required = True

    def clean_username(self):
        username = self.cleaned_data['username']

        if User.objects.filter(username=username).count():
            raise forms.ValidationError('Username already exists')

        if Group.objects.filter(name=username).count():
            raise ValidationError('Username already exists')

        return username

    def clean_email(self):
        email = self.cleaned_data['email']

        if User.objects.filter(email=email).count():
            raise forms.ValidationError('Email already registered')

        return email

    def clean(self):
        cleaned_data = super(RegistrationForm, self).clean()

        if check_registration_enabled() == 'INVITE':
            email = cleaned_data.get('email')
            token = cleaned_data.get('token')

            if not RegistrationToken.objects.filter(email=email, token=token).count():
                raise forms.ValidationError('Invalid Token')

        return cleaned_data

    def register_user(self):
        username = self.cleaned_data['username']
        email = self.cleaned_data['email']

        new_user = User()
        new_user.username = username
        new_user.email = email

        # Create random password for initial user creation
        random_password = User.objects.make_random_password(length=128)
        new_user.set_password(random_password)
        new_user.save()

        if check_registration_enabled() == 'INVITE':
            token = self.cleaned_data['token']
            RegistrationToken.objects.filter(email=email, token=token).delete()

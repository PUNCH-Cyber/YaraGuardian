from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.views.generic import View, TemplateView, FormView
from django.contrib.auth import login, logout
from django.urls import reverse, reverse_lazy
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm

from core.permissions import LoginRequiredModifiedMixin, RegistrationIsEnabledMixin
from core.services import check_registration_enabled

from .forms import RegistrationForm


class Index(LoginRequiredModifiedMixin, TemplateView):
    template_name = 'application/Index.html'


class Healthz(View):

    def get(self, request, *args, **kwargs):
        return HttpResponse(status=200)


class Login(FormView):
    form_class = AuthenticationForm
    template_name = 'prelogin/Login.html'
    success_url = reverse_lazy('Index')

    def registration_enabled(self):
        return check_registration_enabled()

    def social_login_enabled(self):
        supported_backends = ['social_core.backends.google.GoogleOAuth2']
        available_backends = set(settings.AUTHENTICATION_BACKENDS) & set(supported_backends)

        if available_backends:
            return True
        else:
            return False

    def form_valid(self, form):
        login(self.request, form.get_user())
        return super(Login, self).form_valid(form)


class RecoverPassword(FormView):
    template_name = 'prelogin/RecoverPassword.html'
    success_url = reverse_lazy('Login')
    form_class = PasswordResetForm

    def form_valid(self, form):
        form.save(request=self.request)
        return super(RecoverPassword, self).form_valid(form)


class RegisterAccount(RegistrationIsEnabledMixin, FormView):
    template_name = 'prelogin/RegisterAccount.html'
    success_url = reverse_lazy('Login')
    form_class = RegistrationForm

    def token_required(self):
        if check_registration_enabled() == "INVITE":
            return True
        return False

    def form_valid(self, form):
        form.register_user()
        email = form.cleaned_data['email']
        password_reset = PasswordResetForm({'email': email})

        if password_reset.is_valid():
            password_reset.save(request=self.request)

        return super(RegisterAccount, self).form_valid(form)


class Logout(LoginRequiredModifiedMixin, View):

    def get(self, request, *args, **kwargs):
        logout(request)
        return HttpResponseRedirect(reverse('Login'))

from django.urls import reverse_lazy
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin

from .services import check_registration_enabled


class LoginRequiredModifiedMixin(LoginRequiredMixin):
    login_url = reverse_lazy('Login')


class UserIsAdminMixin(UserPassesTestMixin):

    def test_func(self):
        return self.request.user.is_superuser


class UserIsStaffMixin(UserPassesTestMixin):

    def test_func(self):
        return self.request.user.is_staff


class RegistrationIsEnabledMixin(UserPassesTestMixin):

    def test_func(self):
        return check_registration_enabled()

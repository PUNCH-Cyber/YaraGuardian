from django.contrib import admin
from django.contrib.auth import get_user_model

from .services import get_admin_account
from .models import GroupMeta, RegistrationToken

User = get_user_model()

# Globally disable delete selected
admin.site.disable_action('delete_selected')


class UserAdmin(admin.ModelAdmin):
    actions = ['make_active', 'make_inactive']
    exclude = ('password', 'first_name', 'last_name')
    list_display = ('email', 'last_login', 'is_active', 'is_staff', 'is_superuser')

    def get_queryset(self, request):
        qs = super(UserAdmin, self).get_queryset(request)
        return qs.exclude(pk=get_admin_account().pk)

    def make_active(self, request, queryset):
        queryset.update(is_active=True)

    def make_inactive(self, request, queryset):
        queryset.update(is_active=False)

    make_active.short_description = "Mark selected users as active"
    make_inactive.short_description = "Mark selected users as inactive"


class GroupMetaAdmin(admin.ModelAdmin):
    actions = []
    list_display = ('group', 'owner', 'source_required', 'category_required',
                    'nonprivileged_submission_status')

    def get_queryset(self, request):
        qs = super(GroupMetaAdmin, self).get_queryset(request)
        return qs.exclude(owner=get_admin_account())


class RegistrationTokenAdmin(admin.ModelAdmin):
    actions = ['delete_selected']
    list_display = ('token', 'email')


admin.site.register(User, UserAdmin)
admin.site.register(GroupMeta, GroupMetaAdmin)
admin.site.register(RegistrationToken, RegistrationTokenAdmin)

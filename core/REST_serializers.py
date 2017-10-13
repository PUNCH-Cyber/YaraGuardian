from rest_framework import serializers

from .models import GroupMeta
from rules.models import YaraRule


class StringListField(serializers.ListField):
    child = serializers.CharField()


class PublicGroupSerializer(serializers.Serializer):
    name = serializers.CharField(read_only=True)
    owner = serializers.SerializerMethodField()
    rule_count = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()

    def get_owner(self, obj):
        return obj.groupmeta.owner.username

    def get_rule_count(self, obj):
        return YaraRule.objects.filter(owner=obj).count()

    def get_member_count(self, obj):
        return obj.user_set.count()


class PublicUserSerializer(serializers.Serializer):
    username = serializers.CharField(read_only=True)


class PrivateGroupSerializer(serializers.Serializer):

    name = serializers.CharField(read_only=True)
    owner = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()

    source_required = serializers.SerializerMethodField()
    source_options = serializers.SerializerMethodField()

    category_required = serializers.SerializerMethodField()
    category_options = serializers.SerializerMethodField()

    nonprivileged_submission_status = serializers.SerializerMethodField()

    rule_count = serializers.SerializerMethodField()

    def get_owner(self, obj):
        return obj.groupmeta.owner.username

    def get_rule_count(self, obj):
        return YaraRule.objects.filter(owner=obj).count()

    def get_members(self, obj):
        member_listing = {}
        members = obj.user_set.all()

        for member_object in members:

            if obj.groupmeta.owner == member_object:
                group_membership_status = 'owner'

            elif member_object in obj.groupmeta.admins.all():
                group_membership_status = 'admin'

            else:
                group_membership_status = 'member'

            member_listing[member_object.username] = {'membership': group_membership_status}

        return member_listing

    def get_source_required(self, obj):
        return obj.groupmeta.source_required

    def get_source_options(self, obj):
        return obj.groupmeta.source_options

    def get_category_required(self, obj):
        return obj.groupmeta.category_required

    def get_category_options(self, obj):
        return obj.groupmeta.category_options

    def get_nonprivileged_submission_status(self, obj):
        return obj.groupmeta.nonprivileged_submission_status


class GroupMetaUpdateSerializer(serializers.Serializer):
    source_required = serializers.BooleanField()
    category_required = serializers.BooleanField()
    nonprivileged_submission_status = serializers.ChoiceField(YaraRule.STATUS_CHOICES)

    def update(self, instance, validated_data):
        instance.source_required = validated_data.get('source_required',
                                                      instance.source_required)

        instance.category_required = validated_data.get('category_required',
                                                        instance.category_required)

        instance.nonprivileged_submission_status = validated_data.get('nonprivileged_submission_status',
                                                                      instance.nonprivileged_submission_status)

        instance.save()
        return instance


class PrivateUserSerializer(serializers.Serializer):

    username = serializers.CharField(read_only=True)

    email = serializers.EmailField()

    api_token = serializers.CharField(source='auth_token', read_only=True)

    groups = serializers.SerializerMethodField()

    def get_groups(self, obj):
        group_listing = {}
        groups = obj.groups.all()

        for group_object in groups:
            group_meta = group_object.groupmeta

            if group_meta.owner == obj:
                group_membership_status = 'owner'

            elif obj in group_meta.admins.all():
                group_membership_status = 'admin'

            else:
                group_membership_status = 'member'

            group_listing[group_object.name] = {'membership': group_membership_status,
                                                'member_count': group_object.user_set.count(),
                                                'admin_count': group_object.groupmeta.admins.count(),
                                                'rule_count': YaraRule.objects.filter(owner=group_object).count()}

        return group_listing

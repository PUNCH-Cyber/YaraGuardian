import datetime

from rest_framework import serializers
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from core.REST_serializers import PublicUserSerializer
from core.REST_permissions import group_admin

from .models import YaraRule, YaraRuleComment
from .services import parse_rule_submission, generate_kwargs_from_parsed_rule


class YaraRuleCommentSerializer(serializers.Serializer):
    content = serializers.CharField()
    poster = PublicUserSerializer(read_only=True)
    id = serializers.IntegerField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    def retrieve_request_user(self):
        request = self.context.get("request")
        request_user = request.user
        return request_user

    def create(self, validated_data):
        # Retrieve rule object identifier from calling view kwargs
        rule_identifier = self.context['view'].kwargs['rule_pk']

        try:
            rule_object = YaraRule.objects.get(id=rule_identifier)
        except:
            raise serializers.ValidationError("Non-existent rule")
        else:
            validated_data['rule'] = rule_object

        # Generate timestamps
        validated_data['created'] = datetime.datetime.now()
        validated_data['modified'] = datetime.datetime.now()

        # Retrieve submitting user
        validated_data['poster'] = self.retrieve_request_user()

        return YaraRuleComment.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.modified = datetime.datetime.now()
        instance.content = validated_data.get('content', instance.content)
        instance.save()
        return instance


class YaraRuleStatsSerializer(serializers.Serializer):
    tag_list = serializers.SerializerMethodField()
    category_list = serializers.SerializerMethodField()
    metakey_list = serializers.SerializerMethodField()
    source_list = serializers.SerializerMethodField()
    import_list = serializers.SerializerMethodField()
    scope_list = serializers.SerializerMethodField()
    submitter_list = serializers.SerializerMethodField()
    tag_count = serializers.SerializerMethodField()
    metakey_count = serializers.SerializerMethodField()
    source_count = serializers.SerializerMethodField()
    category_count = serializers.SerializerMethodField()
    active_count = serializers.SerializerMethodField()
    inactive_count = serializers.SerializerMethodField()
    pending_count = serializers.SerializerMethodField()
    rejected_count = serializers.SerializerMethodField()
    name_conflict_count = serializers.SerializerMethodField()
    logic_collision_count = serializers.SerializerMethodField()
    missing_dependency_count = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        # Set which fields should be used at point of initializing
        fields = kwargs.pop('fields', None)
        super(YaraRuleStatsSerializer, self).__init__(*args, **kwargs)

        if fields is not None:
            allowed = set(fields)
            existing = set(self.fields.keys())

            for field_name in existing - allowed:
                self.fields.pop(field_name)

    def get_tag_list(self, obj):
        return obj.tag_list()

    def get_category_list(self, obj):
        return obj.category_list()

    def get_metakey_list(self, obj):
        return obj.metakey_list()

    def get_source_list(self, obj):
        return obj.source_list()

    def get_import_list(self, obj):
        return obj.import_list()

    def get_scope_list(self, obj):
        return obj.scope_list()

    def get_submitter_list(self, obj):
        return obj.submitter_list()

    def get_tag_count(self, obj):
        return obj.tag_count()

    def get_metakey_count(self, obj):
        return obj.metakey_count()

    def get_source_count(self, obj):
        return obj.source_count()

    def get_category_count(self, obj):
        return obj.category_count()

    def get_active_count(self, obj):
        return obj.active_count()

    def get_inactive_count(self, obj):
        return obj.inactive_count()

    def get_pending_count(self, obj):
        return obj.pending_count()

    def get_rejected_count(self, obj):
        return obj.rejected_count()

    def get_name_conflict_count(self, obj):
        return obj.name_conflict_count()

    def get_logic_collision_count(self, obj):
        return obj.logic_collision_count()

    def get_missing_dependency_count(self, obj):
        return obj.missing_dependency_count()

    def to_representation(self, obj):
        data = super().to_representation(obj)
        group_context = self.context.get('group_context', None)

        if group_context:
            data['source_options'] = group_context.groupmeta.source_options
            data['category_options'] = group_context.groupmeta.category_options

        return data


class YaraRuleSerializer(serializers.Serializer):
    STATUS_CHOICES = [entry[0] for entry in YaraRule.STATUS_CHOICES]

    source = serializers.CharField(required=False)
    category = serializers.CharField(required=False)
    rule_content = serializers.CharField(required=False)
    status = serializers.ChoiceField(required=False, choices=STATUS_CHOICES)

    def __init__(self, *args, **kwargs):
        super(YaraRuleSerializer, self).__init__(*args, **kwargs)

        try:
            source_blank = not self.retrieve_request_group().groupmeta.source_required
            self.fields['source'] = serializers.ChoiceField(choices=self.retrieve_sources(),
                                                            allow_blank=source_blank)

            category_blank = not self.retrieve_request_group().groupmeta.category_required
            self.fields['category'] = serializers.ChoiceField(choices=self.retrieve_categories(),
                                                              allow_blank=category_blank)

            self.fields['rule_content'].required = True

        except AttributeError:
            pass

    def retrieve_request_user(self):
        request = self.context.get("request")
        request_user = request.user
        return request_user

    def retrieve_request_group(self):
        request = self.context.get("request")
        group_name = request.resolver_match.kwargs.get('group_name')
        group = Group.objects.get(name=group_name)
        return group

    def retrieve_sources(self):
        return self.retrieve_request_group().groupmeta.source_options

    def retrieve_categories(self):
        return self.retrieve_request_group().groupmeta.category_options

    def get_formatted_rule(self, obj):
        return obj.format_rule()

    def get_dependencies(self, obj):
        dependencies = {'count': 0,
                        'available': [],
                        'missing': []}

        for dependency_name in obj.dependencies:
            try:
                dependency_rule = YaraRule.objects.get(name=dependency_name, owner=obj.owner)
                dependencies['available'].append(dependency_rule.name)
                # Use to return full dependency content, but we might just do name list for now
                # dependencies['available'][dependency_rule.name] = dependency_rule.format_rule()

            except MultipleObjectsReturned:
               dependency_rule =  YaraRule.objects.filter(name=dependency_name, owner=obj.owner)[0]
               dependencies['available'].append(dependency_rule.name)

            except ObjectDoesNotExist:
                dependencies['missing'].append(dependency_name)

            dependencies['count'] += 1

        return dependencies

    def to_representation(self, obj):
        return {
            'id': obj.id,
            'name': obj.name,
            'source': obj.source,
            'category': obj.category,
            'status': obj.status,
            'tags': obj.tags,
            'imports': obj.imports,
            'scopes': obj.scopes,
            'metadata': obj.metadata,
            'dependencies': self.get_dependencies(obj),
            'formatted_rule': self.get_formatted_rule(obj),
            'submitter': PublicUserSerializer(obj.submitter).data,
            'comments': YaraRuleCommentSerializer(obj.yararulecomment_set.all(), many=True).data,
            'created': obj.created,
            'modified': obj.modified
        }

    def create(self, validated_data):
        # Retrieve raw yara content to parse out other fields
        rule_content = validated_data.pop('rule_content')
        submission_results = parse_rule_submission(rule_content)

        # Verify parsing was successful
        if submission_results['parser_error']:
            raise serializers.ValidationError("Unable to parse submitted rule")

        # Process parsed rule
        parsed_rules = submission_results['parsed_rules']

        # If parsing was successful, generate keyword arguments for rule creation
        rule_kwargs = generate_kwargs_from_parsed_rule(parsed_rules.popleft())
        rule_kwargs['owner'] = self.retrieve_request_group()
        rule_kwargs['submitter'] = self.retrieve_request_user()
        rule_kwargs['created'] = datetime.datetime.now()

        for attr, value in rule_kwargs.items():
            if attr not in ('comments',):
                validated_data[attr] = value

        # Ensure status is designated
        validated_data['status'] = validated_data.get('status', YaraRule.INACTIVE_STATUS)

        # If guest account, set status to pre-determined value
        if not group_admin(self.context.get('request')):
            validated_data['status'] = self.retrieve_request_group().groupmeta.nonprivileged_submission_status

        # Save the new rule and return as response
        new_rule = YaraRule(**validated_data)
        new_rule.save()

        # Process extracted comments
        YaraRuleComment.objects.process_extracted_comments(new_rule, rule_kwargs['comments'])

        return new_rule

    def update(self, instance, validated_data):
        instance.status = validated_data.get('status', instance.status)
        instance.source = validated_data.get('source', instance.source)
        instance.category = validated_data.get('category', instance.category)
        instance.modified = datetime.datetime.now()

        rule_content = validated_data.get('rule_content')

        # Verify yara content was actually submitted and attempt to parse
        if rule_content:
            submission_results = parse_rule_submission(rule_content)

            if submission_results['parser_error']:
                raise serializers.ValidationError("Unable to parse submitted rule")

            parsed_rules = submission_results['parsed_rules']

            # If parsing was successful, generate keyword arguments for rule updates
            rule_kwargs = generate_kwargs_from_parsed_rule(parsed_rules.popleft())

            # Update instance attributes from the generated keyword arguments
            for attr, value in rule_kwargs.items():
                # Process extracted comments
                if attr == 'comments':
                    YaraRuleComment.objects.process_extracted_comments(instance, value)
                else:
                    # Check for dependency breakage by comparing previous name with new one
                    if (attr == 'name') and (value != instance.name):
                        pass # TO-DO

                    setattr(instance, attr, value)

        # Save the new instance and return as response
        instance.save()
        return instance
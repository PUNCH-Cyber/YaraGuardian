import operator
from functools import reduce

import django_filters

from django.db.models import Q

import dateutil.parser

from core.services import delimit_filtervalue

from .models import YaraRule


class YaraRuleFilter(django_filters.rest_framework.FilterSet):

    identifier = django_filters.CharFilter(method='filter_identifier')

    tagged = django_filters.CharFilter(method='filter_tagged')

    any_tag = django_filters.CharFilter(method='filter_any_tag')

    all_tags = django_filters.CharFilter(method='filter_all_tags')

    without_tag = django_filters.CharFilter(method='filter_without_tag')

    any_import = django_filters.CharFilter(method='filter_any_import')

    all_imports = django_filters.CharFilter(method='filter_all_imports')

    any_scope = django_filters.CharFilter(method='filter_any_scope')

    all_scopes = django_filters.CharFilter(method='filter_all_scopes')

    any_metakey = django_filters.CharFilter(method='filter_any_metakey')

    all_metakeys = django_filters.CharFilter(method='filter_all_metakeys')

    any_dependency = django_filters.CharFilter(method='filter_any_dependency')

    all_dependencies =  django_filters.CharFilter(method='filter_all_dependencies')

    logic_hash = django_filters.CharFilter(lookup_expr='iexact')

    name = django_filters.CharFilter(lookup_expr='iexact')

    name_contains = django_filters.CharFilter(field_name='name', lookup_expr='icontains')

    name_startswith = django_filters.CharFilter(field_name='name', lookup_expr='istartswith')

    name_endswith = django_filters.CharFilter(field_name='name', lookup_expr='iendswith')

    metavalue_contains = django_filters.CharFilter(method='filter_metavalue_contains')

    metavalue_startswith = django_filters.CharFilter(method='filter_metavalue_startswith')

    metavalue_endswith = django_filters.CharFilter(method='filter_metavalue_endswith')

    metakey_contains = django_filters.CharFilter(method='filter_metakey_contains')

    metakey_startswith = django_filters.CharFilter(method='filter_metakey_startswith')

    metakey_endswith = django_filters.CharFilter(method='filter_metakey_endswith')

    created_after = django_filters.CharFilter(method='filter_created_after')

    created_before = django_filters.CharFilter(method='filter_created_before')

    modified_after = django_filters.CharFilter(method='filter_modified_after')

    modified_before = django_filters.CharFilter(method='filter_modified_before')

    submitter = django_filters.CharFilter(method='filter_submitter')

    source = django_filters.CharFilter(method='filter_source')

    category = django_filters.CharFilter(method='filter_category')

    status = django_filters.CharFilter(lookup_expr='iexact')

    comment_contains = django_filters.CharFilter(method='filter_comment_contains')

    class Meta:
        # Prevent automatic field generation
        # as many of the field types are not supported
        fields = []
        model = YaraRule

    def filter_tagged(self, queryset, name, value):

        if value in ('true', 'True', 'TRUE'):
            return queryset.exclude(tags__len=0)

        elif value in ('false', 'False', 'FALSE'):
            return queryset.filter(tags__len=0)

        else:
            return queryset

    def filter_any_tag(self, queryset, name, value):
        tags = delimit_filtervalue(value)
        return queryset.filter(tags__overlap=tags)

    def filter_all_tags(self, queryset, name, value):
        tags = delimit_filtervalue(value)
        return queryset.filter(tags__contains=tags)

    def filter_without_tag(self, queryset, name, value):
        tags = delimit_filtervalue(value)
        return queryset.exclude(tags__overlap=tags)

    def filter_any_import(self, queryset, name, value):
        imports = delimit_filtervalue(value)
        return queryset.filter(imports__overlap=imports)

    def filter_all_imports(self, queryset, name, value):
        imports = delimit_filtervalue(value)
        return queryset.filter(imports__contains=imports)

    def filter_any_scope(self, queryset, name, value):
        scopes = delimit_filtervalue(value)
        return queryset.filter(scopes__overlap=scopes)

    def filter_all_scopes(self, queryset, name, value):
        scopes = delimit_filtervalue(value)
        return queryset.filter(scopes__contains=scopes)

    def filter_any_metakey(self, queryset, name, value):
        metakeys = delimit_filtervalue(value)
        return queryset.filter(metadata__has_any_keys=metakeys)

    def filter_all_metakeys(self, queryset, name, value):
        metakeys = delimit_filtervalue(value)
        return queryset.filter(metadata__has_keys=metakeys)

    def filter_any_dependency(self, queryset, name, value):
        dependencies = delimit_filtervalue(value)
        return queryset.filter(dependencies__overlap=dependencies)

    def filter_all_dependencies(self, queryset, name, value):
        dependencies = delimit_filtervalue(value)
        return queryset.filter(dependencies__contains=dependencies)

    def filter_identifier(self, queryset, name, value):
        identifiers = [int(ID) for ID in delimit_filtervalue(value) if ID.isdigit()]
        return queryset.filter(pk__in=identifiers)

    def filter_metavalue_contains(self, queryset, name, value):
        filter_args = []
        metakey_filter = []

        for metakey in queryset.metakey_list():
            qkwargs = {'metadata__{}__icontains'.format(metakey): value}
            metakey_filter.append(Q(**qkwargs))

        if metakey_filter:
            filter_args.append(reduce(operator.or_, metakey_filter))

        return queryset.filter(*filter_args)

    def filter_metavalue_startswith(self, queryset, name, value):
        filter_args = []
        metakey_filter = []

        for metakey in queryset.metakey_list():
            if not value.startswith("\""):
                value = "\"{}".format(value)
            qkwargs = {'metadata__{}__istartswith'.format(metakey): value}
            metakey_filter.append(Q(**qkwargs))

        filter_args.append(reduce(operator.or_, metakey_filter))
        return queryset.filter(*filter_args)

    def filter_metavalue_endswith(self, queryset, name, value):
        filter_args = []
        metakey_filter = []

        for metakey in queryset.metakey_list():
            if not value.endswith("\""):
                value = "{}\"".format(value)
            qkwargs = {'metadata__{}__iendswith'.format(metakey): value}
            metakey_filter.append(Q(**qkwargs))

        filter_args.append(reduce(operator.or_, metakey_filter))
        return queryset.filter(*filter_args)

    def filter_metakey_contains(self, queryset, name, value):
        metakey_params = []

        for key_value in queryset.metakey_list():
            if value in key_value:
                metakey_params.append(key_value)

        return queryset.filter(metadata__has_any_keys=metakey_params)

    def filter_metakey_startswith(self, queryset, name, value):
        metakey_params = []

        for key_value in queryset.metakey_list():
            if key_value.startswith(value):
                metakey_params.append(key_value)

        return queryset.filter(metadata__has_any_keys=metakey_params)

    def filter_metakey_endswith(self, queryset, name, value):
        metakey_params = []

        for key_value in queryset.metakey_list():
            if key_value.endswith(value):
                metakey_params.append(key_value)

        return queryset.filter(metadata__has_any_keys=metakey_params)

    def filter_created_after(self, queryset, name, value):
        try:
            value = dateutil.parser.parse(value)
        except:
            pass

        return queryset.filter(created__gte=value)

    def filter_created_before(self, queryset, name, value):
        try:
            value = dateutil.parser.parse(value)
        except:
            pass

        return queryset.filter(created__lt=value)

    def filter_modified_after(self, queryset, name, value):
        try:
            value = dateutil.parser.parse(value)
        except:
            pass

        return queryset.filter(modified__gte=value)

    def filter_modified_before(self, queryset, name, value):
        try:
            value = dateutil.parser.parse(value)
        except:
            pass

        return queryset.filter(modified__lt=value)

    def filter_submitter(self, queryset, name, value):
        submitters = delimit_filtervalue(value)

        try:
            return queryset.filter(submitter__in=[int(user) for user in submitters])
        except ValueError:
            pass

        return queryset.filter(submitter__username__in=submitters)

    def filter_source(self, queryset, name, value):
        sources = delimit_filtervalue(value)
        return queryset.filter(source__in=sources)

    def filter_category(self, queryset, name, value):
        categories = delimit_filtervalue(value)
        return queryset.filter(category__in=categories)

    def filter_comment_contains(self, queryset, name, value):
        return queryset.filter(yararulecomment__content__icontains=value)

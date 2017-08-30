
import re

from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, CreateAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from core.services import get_group_or_404

from core.REST_permissions import (IsGroupMember,
                                   IsGroupAdminOrReadOnly,
                                   IsGroupAdminOrAddMethod,
                                   group_admin)

from .REST_filters import YaraRuleFilter
from .models import YaraRule
from .services import build_yarafile, parse_rule_submission

from .REST_serializers import (YaraRuleSerializer,
                               YaraRuleStatsSerializer,
                               YaraRuleCommentSerializer)


def get_queryset(group_context, query_params=None):

    queryset = YaraRule.objects.filter(owner=group_context)

    if query_params:
        queryset = YaraRuleFilter(query_params, queryset=queryset).qs

    return queryset


def paginate_queryset(queryset, view, serializer_class=None):
    page = view.paginator.paginate_queryset(queryset, view.request, view=view)

    # Check if explicit serializer class was defined
    if not serializer_class:
        serializer_class = view.serializer_class

    if page is not None:
        serializer = serializer_class(page, many=True)
        return view.paginator.get_paginated_response(serializer.data)

    serializer = serializer_class(queryset, many=True)
    return Response(serializer.data)


class RuleSetPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 1000

    def get_paginated_response(self, data):
        # Populate non-page-related query params for reference
        query_params = {}

        for key, value in self.request.query_params.items():
            if key != 'page':
                query_params[key] = value

        # Remove page parameter references from absolute URI for base search reference
        base_search = re.sub(r'(\?|&)page=\d+', '', self.request.build_absolute_uri())
        current_page = self.request.query_params.get(self.page_query_param, 1)

        paginated_response = {'result_count': self.page.paginator.count,
                              'page_count': self.page.paginator.num_pages,
                              'current_page': current_page,
                              'query_params': query_params,
                              'base_search':  base_search,
                              'next': self.get_next_link(),
                              'previous': self.get_previous_link(),
                              'results': data}

        return Response(paginated_response)


class RulesetsListingView(APIView):
    """
    Lists all application rulesets.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        groups = request.user.groups.all()
        return Response([group.name for group in groups])


class RulesetView(CreateAPIView):
    """
    Create new rule.
    """
    serializer_class = YaraRuleSerializer
    permission_classes = [IsGroupAdminOrAddMethod]


class RulesetSearchView(ListAPIView):
    """
    Search for rules that match the provided criteria.
    """
    paginator = RuleSetPagination()
    permission_classes = [IsGroupMember]
    filter_class = YaraRuleFilter

    def get_queryset(self):
        group_context = get_group_or_404(self.kwargs['group_name'])
        queryset = YaraRule.objects.filter(owner=group_context)
        return queryset

    def get_serializer_class(self):
        return YaraRuleSerializer

    def filter_queryset(self, queryset):
        return self.filter_class(self.request.query_params, queryset=queryset).qs.order_by('name')


class RulesetStatsView(APIView):
    """
    Retrieve stats on a set of rules.
    """
    permission_classes = [IsGroupMember]
    serializer_class = YaraRuleStatsSerializer

    def get(self, request, group_name):
        response_content = {}
        group_context = get_group_or_404(group_name)
        serializer_context = {'group_context': group_context}
        queryset = get_queryset(group_context, query_params=request.query_params)

        # Return only the stats that are being specifically filtered for
        if 'filter' in request.query_params:
            fields = set(request.query_params.getlist('filter'))
            serializer = self.serializer_class(queryset,
                                               fields=fields,
                                               context=serializer_context)

        # Return all available stats
        else:
            serializer = self.serializer_class(queryset, context=serializer_context)

        return Response(serializer.data)


class RulesetDeconflictView(APIView):
    """
    Deconflict / Merge Logic Collisions
    """
    permission_classes = [IsGroupAdminOrReadOnly]

    def patch(self, request, group_name):
        group_context = get_group_or_404(group_name)

        if request.query_params:
            # Filter and deconflict based on query params
            queryset = get_queryset(group_context, query_params=request.query_params)
        else:
            # Deconflict all
            queryset = YaraRule.objects.filter(owner=group_context)

        response_content = queryset.deconflict_logic()

        return Response(response_content)


class RulesetExportView(APIView):
    """
    Export rules
    """
    permission_classes = [IsGroupMember]

    def get(self, request, group_name):
        # Specify metadata of file object
        file_meta = 'attachment; filename="RuleExport.yara"'

        # Filter based on query params and float dependent rules towards bottom
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context, query_params=request.query_params)

        # Build rule file
        rule_file = build_yarafile(queryset)

        response = HttpResponse(content=rule_file.getvalue())
        response['Content-Type'] = 'application/text'
        response['Content-Disposition'] = file_meta

        return response


class RulesetBulkEditView(APIView):
    """
    post:
    Add rules in bulk to specified ruleset.
    patch:
    Edit rules in bulk to specified ruleset.
    delete:
    Delete rules in bulk to specified ruleset.
    """
    permission_classes = [IsGroupAdminOrAddMethod]

    def post(self, request, group_name):
        response_content= {'errors': [],
                           'warnings': [],
                           'rule_upload_count': 0,
                           'rule_collision_count': 0}

        submitter = request.user
        group_context = get_group_or_404(group_name)

        # Retrieve submitted yara rule content
        submissions = request.data.getlist('rule_content')

        # Only owners and admins can submit ACTIVE or INACTIVE rules
        if group_admin(request):
            if request.data.get('active'):
                status = YaraRule.ACTIVE_STATUS
            else:
                status = YaraRule.INACTIVE_STATUS
        # Rules from others are automatically put into pending status
        else:
            status = YaraRule.PENDING_STATUS

        # Check for source and category
        source = request.data.get('source', '')
        category = request.data.get('category', '')

        # Check for in-line modifications
        add_tags = request.data.get('add_tags', None)
        prepend_name = request.data.get('prepend_name', None)
        append_name = request.data.get('append_name', None)

        add_metadata = {metakey[13:] : metavalue
                        for metakey, metavalue in request.data.items()
                        if metakey.startswith('set_metadata_')}

        # Process each submission
        for raw_submission in submissions:
            submission_results = parse_rule_submission(raw_submission)
            # Inspect the submission results
            parsed_rules = submission_results['parsed_rules']
            parsing_error = submission_results['parser_error']
            # Identify any parsing errors that occur
            if parsing_error:
                response_content['errors'].append(parsing_error)
            else:
                # Save successfully parsed rules
                save_results = YaraRule.objects.process_parsed_rules(parsed_rules,
                                                                     source, category,
                                                                     submitter, group_context,
                                                                     status=status,
                                                                     add_tags=add_tags,
                                                                     add_metadata=add_metadata,
                                                                     prepend_name=prepend_name,
                                                                     append_name=append_name)

                response_content['errors'] = save_results['errors']
                response_content['warnings'] = save_results['warnings']
                response_content['rule_upload_count'] += save_results['rule_upload_count']
                response_content['rule_collision_count'] += save_results['rule_collision_count']

        return Response(response_content)

    def patch(self, request, group_name):
        group_context = get_group_or_404(group_name)

        if request.query_params:
            # Filter based on query params
            queryset = get_queryset(group_context, query_params=request.query_params)
        else:
            # Do not allow method to occur by setting the queryset to none
            queryset = YaraRule.objects.none()

        rule_count = queryset.count()
        rule_names = list(queryset.values_list('name', flat=True).distinct())

        update_feedback = queryset.bulk_update(request.data)

        response_content = {'modified_rule_count': rule_count,
                            'modified_rule_names': rule_names,
                            'errors': update_feedback['errors'],
                            'warnings': update_feedback['warnings']}

        return Response(response_content)

    def delete(self, request, group_name):
        group_context = get_group_or_404(group_name)

        if request.query_params:
            # Filter based on query params
            queryset = get_queryset(group_context, query_params=request.query_params)
        else:
            # Do not allow method to occur by setting the queryset to none
            queryset = YaraRule.objects.none()

        rule_count = queryset.count()
        rule_names = list(queryset.values_list('name', flat=True).distinct())

        queryset.delete()

        response_content = {'deleted_rule_count': rule_count,
                            'deleted_rule_names': rule_names}

        return Response(response_content)


class RuleDetailsView(APIView):
    """
    get:
    Retrieve specified rule.
    put:
    Replace specified rule.
    patch:
    Update specified rule.
    delete:
    Delete specified rule.
    """
    serializer_class = YaraRuleSerializer
    permission_classes = [IsGroupAdminOrReadOnly]

    def get(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        serializer = self.serializer_class(rule)
        return Response(serializer.data)

    def put(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)

        serializer = self.serializer_class(rule, data=request.data)

        if serializer.is_valid():
            serializer.save()

        return Response(serializer.data)

    def patch(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)

        serializer = self.serializer_class(rule, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()

        return Response(serializer.data)

    def delete(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        rule.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class RuleTagsView(APIView):
    """
    Delete tag from specified rule.
    """
    permission_classes = [IsGroupAdminOrReadOnly]

    def delete(self, request, group_name, rule_pk, tag):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)

        if tag and tag in rule.tags:
            rule.tags.remove(tag)
            rule.save(update_fields=['tags'])

        serializer = YaraRuleSerializer(rule)
        return Response(serializer.data)


class RuleMetadataView(APIView):
    """
    Delete metadata from specified rule.
    """
    permission_classes = [IsGroupAdminOrReadOnly]

    def delete(self, request, group_name, rule_pk, metakey):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)

        if metakey and metakey in rule.metadata:
            rule.metadata.pop(metakey)
            rule.save(update_fields=['metadata'])

        serializer = YaraRuleSerializer(rule)
        return Response(serializer.data)


class RuleCommentsView(APIView):
    """
    get:
    List comments belonging to specified rule.
    post:
    Add comment to specified rule.
    """
    serializer_class = YaraRuleCommentSerializer
    permission_classes = [IsGroupAdminOrReadOnly]

    def get(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        comments = rule.yararulecomment_set.all()
        serializer = self.serializer_class(comments, many=True)
        return Response(serializer.data)

    def post(self, request, group_name, rule_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)

        serializer = self.serializer_class(data=request.data,
                                           context={'request': request,
                                                    'view': self})

        if serializer.is_valid():
            serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class RuleCommentDetailsView(APIView):
    """
    get:
    Retrieve specific rule comment.
    put:
    Update rule comment.
    delete:
    Delete rule comment.
    """
    serializer_class = YaraRuleCommentSerializer
    permission_classes = [IsGroupAdminOrReadOnly]

    def get(self, request, group_name, rule_pk, comment_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        comment = get_object_or_404(rule.yararulecomment_set.all(), pk=comment_pk)

        serializer = self.serializer_class(comment)
        return Response(serializer.data)

    def put(self, request, group_name, rule_pk, comment_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        comment = get_object_or_404(rule.yararulecomment_set.all(), pk=comment_pk)

        serializer = self.serializer_class(comment, data=request.data)

        if serializer.is_valid():
            serializer.save()

        return Response(serializer.data)

    def delete(self, request, group_name, rule_pk, comment_pk):
        group_context = get_group_or_404(group_name)
        queryset = get_queryset(group_context)
        rule = get_object_or_404(queryset, pk=rule_pk)
        comment = get_object_or_404(rule.yararulecomment_set.all(), pk=comment_pk)
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

from django.conf.urls import include, url

from rules.REST_views import (RulesetsListingView,
                              RulesetView,
                              RulesetStatsView,
                              RulesetSearchView,
                              RulesetExportView,
                              RulesetBulkEditView,
                              RulesetDeconflictView,
                              RuleDetailsView,
                              RuleTagsView,
                              RuleMetadataView,
                              RuleCommentsView,
                              RuleCommentDetailsView)

from core.patterns import group_name_pattern, comment_pk_pattern, rule_pk_pattern, metakey_pattern, tag_pattern


urlpatterns = [

    url(r'^$', RulesetsListingView.as_view(),
        name='rulesets'),

    url(r'^{}/$'.format(group_name_pattern),
        RulesetView.as_view(), name='ruleset'),

    url(r'^{}/stats/$'.format(group_name_pattern),
        RulesetStatsView.as_view(), name='ruleset-stats'),

    url(r'^{}/search/$'.format(group_name_pattern),
        RulesetSearchView.as_view(), name='ruleset-search'),
 
    url(r'^{}/export/$'.format(group_name_pattern),
        RulesetExportView.as_view(), name='ruleset-export'),
 
    url(r'^{}/deconflict/$'.format(group_name_pattern),
        RulesetDeconflictView.as_view(), name='ruleset-deconflict'),
 
    url(r'^{}/bulk/$'.format(group_name_pattern),
        RulesetBulkEditView.as_view(), name='ruleset-bulk'),

    url(r'^{}/{}/$'.format(group_name_pattern, rule_pk_pattern),
        RuleDetailsView.as_view(), name='rule-details'),
 
    url(r'^{}/{}/tags/{}/$'.format(group_name_pattern, rule_pk_pattern, tag_pattern),
        RuleTagsView.as_view(), name='rule-tags'),
 
    url(r'^{}/{}/metadata/{}/$'.format(group_name_pattern, rule_pk_pattern, metakey_pattern),
        RuleMetadataView.as_view(), name='rule-metadata'),
 
    url(r'^{}/{}/comments/$'.format(group_name_pattern, rule_pk_pattern),
        RuleCommentsView.as_view(), name='rule-comments'),

    url(r'^{}/{}/comments/{}/$'.format(group_name_pattern, rule_pk_pattern, comment_pk_pattern),
        RuleCommentDetailsView.as_view(),
        name='rule-comment-details'),
]

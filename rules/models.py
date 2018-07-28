from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import ArrayField, HStoreField, JSONField

from django.contrib.auth.models import Group
from plyara import Plyara

from .managers import YaraRuleManager, YaraRuleCommentManager


class YaraRule(models.Model):

    ACTIVE_STATUS = 'active'
    INACTIVE_STATUS = 'inactive'
    PENDING_STATUS = 'pending'
    REJECTED_STATUS = 'rejected'

    STATUS_CHOICES = (
        (ACTIVE_STATUS, 'Active'),
        (INACTIVE_STATUS, 'Inactive'),
        (PENDING_STATUS, 'Pending'),
        (REJECTED_STATUS, 'Rejected')
    )

    # Attributes obtained via rule parser
    name = models.CharField(max_length=128)
    strings = JSONField()
    condition = ArrayField(models.TextField())

    tags = ArrayField(models.CharField(max_length=128), default=list)
    scopes = ArrayField(models.CharField(max_length=10), default=list)
    imports = ArrayField(models.CharField(max_length=128), default=list)
    metadata = HStoreField(default=dict)

    # Listing of rule dependencies
    dependencies = ArrayField(models.TextField(), default=list)

    # Hash value of rule strings and condition to identify logical uniqueness
    logic_hash = models.CharField(max_length=64)

    # Which group owns this rule
    owner = models.ForeignKey(Group, editable=False, on_delete=models.CASCADE,
                              related_name="rule_owner")

    # Who submitted this rule
    submitter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING, 
                                  related_name="rule_submitter")

    # Where did the rule come from
    source = models.CharField(max_length=75, blank=True)

    # What should this rule be run against
    category = models.CharField(max_length=75, blank=True)

    # Status description of the rule (active / inactive)
    status = models.CharField(max_length=75,
                              choices=STATUS_CHOICES,
                              default=ACTIVE_STATUS)

    modified = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True, editable=False)

    # Instantiate custom manager
    objects = YaraRuleManager()

    def save(self, *args, **kwargs):
        super(YaraRule, self).save(*args, **kwargs)

    def format_rule(self):
        raw_rule = {}

        raw_rule['rule_name'] = self.name
        raw_rule['tags'] = self.tags
        raw_rule['imports'] = self.imports
        raw_rule['metadata'] = self.metadata
        raw_rule['strings'] = self.strings
        raw_rule['condition_terms'] = self.condition
        raw_rule['scopes'] = self.scopes

        formatted_rule = Plyara.rebuild_yara_rule(raw_rule)
        return formatted_rule

    def __str__(self):
        return self.name


class YaraRuleComment(models.Model):
    content = models.TextField()
    poster = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rule = models.ForeignKey(YaraRule, on_delete=models.CASCADE)
    modified = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True, editable=False)

    # Instantiate custom manager
    objects = YaraRuleCommentManager()

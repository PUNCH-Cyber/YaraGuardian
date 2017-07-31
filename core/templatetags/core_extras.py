from django import template
from django.template.defaultfilters import stringfilter

from YaraGuardian import VERSION

register = template.Library()


@register.filter
def repeat(string, times):
    return string * times

@register.simple_tag
def version():
    return VERSION

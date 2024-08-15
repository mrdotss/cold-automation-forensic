from django import template

register = template.Library()


@register.filter
def split_string(value, delimiter):
    return value.split(delimiter)


@register.filter
def evidence_status_badge_class(status):
    return {
        'Acquired': 'badge-success',
        'Analyzed': 'badge-warning',
        'Archived': 'badge-info',
    }.get(status, 'badge-secondary')

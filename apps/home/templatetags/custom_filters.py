import os
from django import template
from django.conf import settings

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

@register.filter
def image_exists(image_name):
    image_path = f'assets/img/icons/apps/{image_name}.png'
    full_path = os.path.join(settings.STATIC_ROOT, image_path)

    # Check if the file exists
    if os.path.exists(full_path):
        return image_name

    return 'default'

@register.filter
def to_str(value):
    """converts int to string"""
    return str(value)

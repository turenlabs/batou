# Django template XSS examples

from django.utils.safestring import mark_safe
from django.template import Template, Context


# Template using |safe filter — in a real Django template this would be:
# {{ user_input|safe }}
template_content = '{{ user_bio|safe }}'


def render_profile(request):
    bio = request.POST.get('bio')
    # Vulnerable: mark_safe with user input via f-string
    html = mark_safe(f"<div class='bio'>{bio}</div>")
    return html


def render_comment(request):
    comment = request.POST.get('comment')
    # Vulnerable: mark_safe with string concat
    html = mark_safe("<p>" + comment + "</p>")
    return html

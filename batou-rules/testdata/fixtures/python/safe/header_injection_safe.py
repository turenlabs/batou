from django.http import HttpResponse
import urllib.parse

def set_header_safe(request):
    response = HttpResponse("OK")
    # SAFE: URL-encode the value before setting header
    custom = urllib.parse.quote(request.GET.get('custom', ''))
    response['X-Custom'] = custom
    return response

from django.http import HttpResponse

def set_header(request):
    response = HttpResponse("OK")
    # VULNERABLE: setting header from request input without CRLF sanitization
    response['X-Custom'] = request.GET['custom']
    response['X-User-Token'] = request.POST['token']
    return response

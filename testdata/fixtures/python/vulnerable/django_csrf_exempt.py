# Django CSRF exemption examples

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json


@csrf_exempt
def create_order(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Process order...
        return JsonResponse({'status': 'created'})


@csrf_exempt
def update_profile(request):
    if request.method == 'POST':
        # Update user profile...
        return JsonResponse({'status': 'updated'})

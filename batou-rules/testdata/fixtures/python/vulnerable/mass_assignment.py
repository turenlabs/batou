# Vulnerable: Mass assignment in Python/Django
from django.http import JsonResponse
from myapp.models import User

def create_user(request):
    # VULNERABLE: Django ORM create with unpacked user input
    user = User.objects.create(**request.data)

    # VULNERABLE: Model instantiation with unpacked input
    profile = User(**request.data)

    # VULNERABLE: __dict__.update with user input
    user.__dict__.update(request.data)

    return JsonResponse({"id": user.id})


# VULNERABLE: DRF serializer with fields = '__all__'
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

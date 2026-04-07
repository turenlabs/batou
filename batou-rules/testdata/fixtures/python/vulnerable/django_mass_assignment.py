# Django mass assignment examples

from myapp.models import User, Profile


def create_user(request):
    # Vulnerable: passing all POST data directly to create
    user = User.objects.create(**request.POST)
    return user


def update_profile_api(request):
    # Vulnerable: passing all request.data to update
    Profile.objects.update(**request.data)


def create_from_api(request):
    # Vulnerable: mass assignment with request.data
    profile = Profile.objects.create(**request.data)
    return profile

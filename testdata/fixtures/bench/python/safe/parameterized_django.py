from django.http import JsonResponse, HttpRequest
from django.db import connection
from django.contrib.auth.models import User

# SAFE: Django ORM - automatically parameterized
def search_users(request: HttpRequest) -> JsonResponse:
    query = request.GET.get("q", "")
    users = User.objects.filter(username__icontains=query).values("id", "username", "email")[:50]
    return JsonResponse({"users": list(users)})


# SAFE: Raw SQL with parameterized placeholders (%s)
def get_user_orders(request: HttpRequest) -> JsonResponse:
    user_id = request.GET.get("user_id")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, total, status FROM orders WHERE user_id = %s AND status != %s ORDER BY created_at DESC",
            [user_id, "cancelled"],
        )
        columns = [col[0] for col in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    return JsonResponse({"orders": rows})


# SAFE: Django ORM aggregate query
def category_stats(request: HttpRequest) -> JsonResponse:
    from django.db.models import Count, Avg
    category = request.GET.get("category")
    stats = (
        User.objects.filter(profile__category=category)
        .values("profile__category")
        .annotate(count=Count("id"), avg_age=Avg("profile__age"))
    )
    return JsonResponse({"stats": list(stats)})


# SAFE: Django ORM create (no raw SQL)
def create_post(request: HttpRequest) -> JsonResponse:
    title = request.POST.get("title", "")
    body = request.POST.get("body", "")
    from django.contrib.auth.models import User as AuthUser
    post = AuthUser.objects.create(username=title, email=body)
    return JsonResponse({"id": post.id}, status=201)

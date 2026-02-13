# Django ORM SQL injection examples

from django.db import connection
from myapp.models import User, Product


def search_users_raw(request):
    query = request.GET.get('q')
    # Vulnerable: f-string in objects.raw()
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username LIKE '%{query}%'")
    return users


def search_products_format(request):
    name = request.GET.get('name')
    # Vulnerable: .format() in objects.raw()
    products = Product.objects.raw("SELECT * FROM products WHERE name = '{}'".format(name))
    return products


def search_users_extra(request):
    user_id = request.GET.get('id')
    # Vulnerable: objects.extra() with unsanitized input
    users = User.objects.extra(where=["id = %s" % user_id])
    return users


def raw_cursor_query(request):
    table = request.GET.get('table')
    # Vulnerable: cursor.execute with f-string
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM {table} LIMIT 10")
    return cursor.fetchall()


def raw_cursor_format(request):
    name = request.GET.get('name')
    cursor = connection.cursor()
    # Vulnerable: cursor.execute with .format()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    return cursor.fetchall()

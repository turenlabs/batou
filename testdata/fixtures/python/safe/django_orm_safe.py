# Safe Django ORM usage for testing

from django.db import connection
from myapp.models import User, Product


def search_users_raw(request):
    query = request.GET.get('q')
    # Safe: parameterized query with params argument
    users = User.objects.raw('SELECT * FROM auth_user WHERE username LIKE %s', ['%' + query + '%'])
    return users


def search_products(request):
    name = request.GET.get('name')
    # Safe: using ORM filter
    products = Product.objects.filter(name=name)
    return products


def raw_cursor_query(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    # Safe: parameterized cursor.execute
    cursor.execute('SELECT * FROM auth_user WHERE id = %s', [user_id])
    return cursor.fetchall()

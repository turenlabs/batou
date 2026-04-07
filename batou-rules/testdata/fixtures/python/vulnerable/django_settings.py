# Insecure Django settings file for testing

import os

SECRET_KEY = 'my-insecure-secret-key-12345'

DEBUG = True

ALLOWED_HOSTS = ['*']

SECURE_SSL_REDIRECT = False

SESSION_COOKIE_SECURE = False

CSRF_COOKIE_SECURE = False

SESSION_COOKIE_HTTPONLY = False

CORS_ALLOW_ALL_ORIGINS = True

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'corsheaders',
]

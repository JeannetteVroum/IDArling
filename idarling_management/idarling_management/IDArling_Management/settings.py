"""
Django settings for IDArling_Management project.

Generated by 'django-admin startproject' using Django 3.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import secrets

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# https://humberto.io/blog/tldr-generate-django-secret-key/
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", secrets.token_hex(75))

# By default, SESSION_EXPIRE_AT_BROWSER_CLOSE is set to False,
# which means session cookies will be stored in users’ browsers for as long as SESSION_COOKIE_AGE.
# Use this if you don’t want people to have to log in every time they open a browser.

SESSION_EXPIRE_AT_BROWSER_CLOSE = False if "false" == os.environ.get("DJANGO_SESSION_EXPIRE_AT_BROWSER_CLOSE",
                                                                     "") else True
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False if "false" == os.environ.get("DEBUG", '').lower() else True

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", ['*'])
# ['idarling.fr', 'localhost', '127.0.0.1','www.localhost']

# Application definition

INSTALLED_APPS = [
    'channels',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'IDArling.apps.IdarlingConfig',

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'IDArling_Management.urls'
AUTHENTICATION_BACKENDS = ["IDArling_Management.BackendAuthentification.BackendAuthentification",
                           'django.contrib.auth.backends.ModelBackend',

                           ]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')]
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

ASGI_APPLICATION = 'IDArling_Management.routing.application'

# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases


DATABASES = {  # To modify
    'default': {

        'ENGINE': os.environ.get("SQL_ENGINE", "django.db.backends.postgresql_psycopg2"),
        'NAME': os.environ.get("SQL_DATABASE", "hello_django"),
        'USER': os.environ.get("SQL_USER", "postgres"),
        'PASSWORD': os.environ.get("SQL_PASSWORD", "hello_django"),
        'HOST': os.environ.get("SQL_HOST", "localhost"),
        'PORT': os.environ.get("SQL_PORT", "5432"),
    }
}

# LDAP
LDAP = {  # To modify
    'URL': os.environ.get("LDAP_HOST", "localhost"),
    'PORT': os.environ.get("LDAP_PORT", "389"),
    'BASE_DN': os.environ.get("LDAP_BASE_DN", "dc=ludovic-cruchot,dc=com"),
    'DOMAIN_ALLOWED': os.environ.get("LDAP_DOMAIN_ALLOWED", "ludovic-cruchot.com")
}

LOGGING = {  # To modify
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': os.environ.get("LEVEL_LOGGING", "INFO"),
            'class': 'logging.FileHandler',
            'filename': "/var/log/idarling_management.log",
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': os.environ.get("LEVEL_LOGGING", "INFO"),
            'propagate': True,
        }
    }
}

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]
# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/
AUTH_USER_MODEL = 'IDArling.User'
LANGUAGE_CODE = 'en-us'

DATETIME_FORMAT = "d-M-Y"
TIME_ZONE = 'UTC'

USE_I18N = False

USE_L10N = False

USE_TZ = False

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'

SATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'IDArling_Management/static')

LOGIN_REDIRECT_URL = 'home'

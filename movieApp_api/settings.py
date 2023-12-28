"""
Django settings for movieApp_api project.

Generated by 'django-admin startproject' using Django 4.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.0/ref/settings/
"""

from distutils import config
from pathlib import Path
import cloudinary_storage
import dj_database_url
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-s5q$yc11o!v!qx=ls#2hlgh#&n5%5r3b*o(q9y_#sw^)5j50*+'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False
# APPEND_SLASH = False

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'api',
    'theater',
    'django_jsonform',
    'paypal.standard.ipn',
    'cloudinary',
    'cloudinary_storage',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # 'rest_framework.authentication.TokenAuthentication',
]

ROOT_URLCONF = 'movieApp_api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'movieApp_api.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    'default': {  
        'ENGINE': 'django.db.backends.mysql',  
        'NAME': 'movie_db',  
        'USER': 'root',  
        'PASSWORD': '',  
        'HOST': '127.0.0.1',  
        'PORT': '3306',  
        'OPTIONS': {  
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"  
        }  
    }  
}

DATABASES['default'] = dj_database_url.parse("postgres://movieapp_v8mx_user:Ziz7w9tkQDxQFetR1nTj0nKb9DqOEZpm@dpg-cm1v9smn7f5s73epj1fg-a.oregon-postgres.render.com/movieapp_v8mx")


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_URL = '/static/'
MEDIA_URL = '/media/'

if DEBUG: 
    STATICFILES_DIRS = [BASE_DIR / 'static']
else:
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')


# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'api.CustomUser'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        # 'knox.auth.TokenAuthentication',
    ],
    # Other settings...
}

# settings.py

# from decouple import config

DIALOGFLOW_PROJECT_ID = config('moviechatbot-hkek')
DIALOGFLOW_JSON_KEY_PATH = config('E:\react\ticket-movie-booking\movieApp_api\dialogflow.json')


PAYPAL_CLIENT_ID = 'AelfaP8uCClDYqdvbfACU4NeOipSTSU_N_kBp6CY8vtiRZiH4yaDHoqR62i_vw6MZo_s3cNd6PTZlZAT'
PAYPAL_CLIENT_SECRET = 'EBE2eCqciZ1LWykdhCcOfSfwfHnv_wsNyG2C2rUtT7eYqOeR4VCNqLz-XIbJ3285MA0W8RhNuxj9qPWa'
PAYPAL_MODE = 'sandbox'

PAYPAL_RECEIVER_EMAIL = 'ntmkhue.20it6@vku.udn.vn'
PAYPAL_TEST = True

CLOUDINARY_STORAGE = {
    "CLOUD_NAME": "dm0wmcxlz",
    "API_KEY": "766935793277724",
    "API_SECRET": "9jDYjetU3nojdcMWtNYer5KpCRo"
}

DEFAULT_FILE_STORAGE = "cloudinary_storage.storage.MediaCloudinaryStorage"
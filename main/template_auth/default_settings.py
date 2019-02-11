
"""
These are default settings that are used with in the project. Many of these will need to be used
within the actual project that this app is installed with.

To properly use all the features of this package you must add all of these values to the settings.py
file. Use the the full variable name within the settings without any prefix.

You can copy and paste all of these values to the bottom of the settings.py file. This is the advised
method so that it is easier to adjust the settings.

You will also need to add the urls to the project
    path('auth/', include('template_auth.urls')),
    path('', include('social_django.urls', namespace='social')),

You only need to add the social_django urls if you will be using the social aspect of the project.

"""

import sys, os

from django.conf import settings

BASE_DIR = settings.BASE_DIR

# region App Name
""" 
App name is mainly used for the Django Oauth Toolkit. This is arbitrary and can be changed
to anything that you would like.
"""
# Add your app name here. This will be used in various areas of the application.
APP_NAME = 'main'

OAUTH_APP_NAME = APP_NAME
# endregion

# Only use this if needed
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'shared_templates'),
        ],
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

# Where the user goes after logging in. You must set this to your needs.
LOGIN_REDIRECT_URL = 'admin_site:dashboard'

# Whee the user goes after logging out. You must set this to your needs.
LOGOUT_REDIRECT_URL = '/'

# region Cors settings

CORS_ORIGIN_ALLOW_ALL = True  # Needed since we are dealing with mobile devices

# endregion

# region Email Settings
NO_REPLY_EMAIL = ''
NO_REPLY_EMAIL_PASS = ''

ACTIVATION_EMAIL_SUBJECT = 'Activate your new account'
ACTIVATION_EMAIL_MESSAGE = 'Please click the link below to activate your account.'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_SSL = True
EMAIL_HOST = ''  # Example smtp.zoho.com
EMAIL_PORT = 465
EMAIL_HOST_USER = NO_REPLY_EMAIL
EMAIL_HOST_PASSWORD = NO_REPLY_EMAIL_PASS

# endregion

# region Static Files

STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'sass_processor.finders.CssFinder',
]

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static/")
STATICFILES_DIRS = [
    # The below two are added as a convenience if needed.
    # ('node_modules', os.path.join(BASE_DIR, "node_modules/")),
    # ('shared_static', os.path.join(BASE_DIR, "shared_static")),
]

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, "media/")

SASS_PROCESSOR_ROOT = STATIC_ROOT  # For the Django SASS Processor
NODE_MODULES_URL = STATIC_URL + 'node_modules/'

# SASS_PROCESSOR_INCLUDE_DIRS = [
#     os.path.join(BASE_DIR, 'shared_static'),
# ]
# endregion

# region Rest Framework

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ),

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
    ),

    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    )
}

# endregion

# region Oauth Settings
RESET_PASSWORD_TOKEN_EXPIRE_SECONDS = 86400  # 1 day (in seconds)

ACTIVATE_ACCOUNT_TOKEN_EXPIRE_SECONDS = 604800  # 7 days (in seconds)

ACCESS_TOKEN_EXPIRE_SECONDS = 2592000  # 30 days (in seconds) Also used for manually creating a token.

# reference Django Oauth Toolkit: https://github.com/jazzband/django-oauth-toolkit
OAUTH2_PROVIDER = {
    # this is the list of available scopes
    'SCOPES': {'read': 'Read scope', 'write': 'Write scope', 'groups': 'Access to your groups'},
    'ACCESS_TOKEN_EXPIRE_SECONDS': ACCESS_TOKEN_EXPIRE_SECONDS,   # 30 days (in seconds)
    'REFRESH_TOKEN_EXPIRE_SECONDS': 5184000,  # 60 days (in seconds)
}

# endregion

# region Social Auth Settings
# reference Python Social Auth: https://python-social-auth-docs.readthedocs.io/en/latest/

SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS = ['username', 'first_name', 'last_name', 'email']

# App ID from Facebook "manage apps" portal
SOCIAL_AUTH_FACEBOOK_KEY = ''

SOCIAL_AUTH_POSTGRES_JSONFIELD = True

# App Secret from the Facebook "manage apps" portal
SOCIAL_AUTH_FACEBOOK_SECRET = ''

SOCIAL_AUTH_FACEBOOK_SCOPE = ['email', 'public_profile']

SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
  # 'locale': 'ru_RU',
  'fields': 'id, name, email'
}

# endregion

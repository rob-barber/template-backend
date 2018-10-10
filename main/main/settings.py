"""
Django settings for main project.

Generated by 'django-admin startproject' using Django 2.1.2.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

if DEBUG is False:
    # region Production Settings
    # Import this key from an OS variable to increase security
    with open('/etc/django_secrets/service_backend_secret.txt', 'rt') as f:
        SECRET_KEY = f.read().strip()

    SERVER_BASE_URL = 'http://192.168.1.152'
    ALLOWED_HOSTS = ['*']  # Only allow all if you are dealing with mobile apps or API access to third parties.
    CSRF_COOKIE_SECURE = True  # Means browsers may ensure that https is used in cookie transmission
    SESSION_COOKIE_SECURE = True
    SECURE_CONTENT_TYPE_NOSNIFF = True  # Prevent browsers from guessing content type header
    SECURE_BROWSER_XSS_FILTER = True  # https://docs.djangoproject.com/en/1.11/ref/middleware/#x-content-type-options
    X_FRAME_OPTIONS = 'DENY'


    # endregion
else:
    #region Debug Settings
    # Quick-start development settings - unsuitable for production
    # See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/
    SECRET_KEY = '2l#hds^am9qac0fr++sln%c5p^6*7mq4*z4epyy=dwo5-j(anj'
    SERVER_BASE_URL = ''
    ALLOWED_HOSTS = ['*']
    #endregion

# Add your app name here. This will be used in various areas of the application.
APP_NAME = 'main'

OAUTH_APP_NAME = APP_NAME

# Uncomment and update if you are using a custom user object.
# AUTH_USER_MODEL = 'main.User'


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'oauth2_provider',
    'social_django',
    'corsheaders',
    'rest_framework',
    'main_auth.apps.MainAuthConfig'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
]

ROOT_URLCONF = 'main.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'main.wsgi.application'


#region Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}
#endregion

#region Password Validators
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators

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
#endregion

#region Language and Timezone Configuration
# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True
#endregion

#region Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static/")
#endregion

#region Email and Default Email Values Configuration
# Email address, and password, to send password recovery emails from.
NO_REPLY_EMAIL = ''
NO_REPLY_EMAIL_PASS = ''

ACTIVATION_EMAIL_SUBJECT = 'Activate your new account'
ACTIVATION_EMAIL_MESSAGE = 'Please click the link below to activate your account.'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_SSL = True
EMAIL_HOST = '' # Example smtp.zoho.com
EMAIL_PORT = 465
EMAIL_HOST_USER = NO_REPLY_EMAIL
EMAIL_HOST_PASSWORD = NO_REPLY_EMAIL_PASS
#endregion

#region Security Configuration
SESSION_COOKIE_AGE = 86400  # One day in seconds

AUTHENTICATION_BACKENDS = [
    'oauth2_provider.backends.OAuth2Backend',
    'social_core.backends.facebook.FacebookOAuth2',
    'django.contrib.auth.backends.ModelBackend',
]

CORS_ORIGIN_ALLOW_ALL = True  # Needed since we are dealing with mobile devices

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

ACTIVATE_ACCOUNT_TOKEN_EXPIRE_SECONDS = 604800 # 7 days (in seconds)
RESET_PASSWORD_TOKEN_EXPIRE_SECONDS = 86400 # 1 day (in seconds)

# Also used by Oauth Toolkit
ACCESS_TOKEN_EXPIRE_SECONDS = 2592000 # 30 days (in seconds) Also used for manually creating a token.

OAUTH2_PROVIDER = {
    # this is the list of available scopes
    'SCOPES': {'read': 'Read scope', 'write': 'Write scope', 'groups': 'Access to your groups'},
    'ACCESS_TOKEN_EXPIRE_SECONDS': ACCESS_TOKEN_EXPIRE_SECONDS,   # 30 days (in seconds)
    'REFRESH_TOKEN_EXPIRE_SECONDS': 5184000,  # 60 days (in seconds)
}
#endregion

#region Social Login Providers Configuration
# Customize for whatever Facebook fields are necessary for logging in.
SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS = ['username', 'first_name', 'last_name', 'email']

# App ID from Facebook "manage apps" portal
SOCIAL_AUTH_FACEBOOK_KEY = ''

# App Secret from the Facebook "manage apps" portal
SOCIAL_AUTH_FACEBOOK_SECRET = ''
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email', 'public_profile']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
  # 'locale': 'ru_RU',
  'fields': 'id, name, email'
}
#endregion
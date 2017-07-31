import os
import re
import json
from unipath import Path
from distutils.util import strtobool
from django.core.exceptions import ImproperlyConfigured

# Project base path
BASE_DIR = Path(__file__).absolute().ancestor(2)

# Project root directories
MEDIA_ROOT = BASE_DIR.child('media')
LOGGING_ROOT = BASE_DIR.child('logs')
TEMPLATE_ROOT = BASE_DIR.child('templates')

# Ensure project root directories exists
MEDIA_ROOT.mkdir()
LOGGING_ROOT.mkdir()
TEMPLATE_ROOT.mkdir()

# Use OS environment variables to load sensitive or dynamic settings
settings_environment = os.environ

# Alternatively, we can use JSON file
# with open(os.path.join(BASE_DIR, "config.json")) as f:
#     settings_environment = json.loads(f.read())

# Leverage setting retrieval function to abstract the retrieval and manipulation
# of sensitive or dynamic settings so we can load from either the OS environment or
# a configuration file without making alot of changes throughout
def retrieve_setting(setting, env=settings_environment,
                     arrayset=False, arraypattern='; |, |;|,| ',
                     defaultset=False, defaultval=None, boolset=False):

    if defaultset:
        # Attempt to retrieve setting that is optional to be in environment
        setting_value = env.get(setting, defaultval)
    else:
        # Attempt to retrieve setting that is required to be in environment
        try:
            setting_value = env[setting]
        except KeyError:
            error_message = "{} variable is not set".format(setting)
            raise ImproperlyConfigured(error_message)

    # Setting formatting conversions
    if boolset:
        # Convert to Boolean value
        try:
            return bool(strtobool(setting_value))
        except ValueError:
            error_message = "{} variable cannot be converted to bool value"
            raise ImproperlyConfigured(error_message)

    elif arrayset:
        if isinstance(setting_value, list):
            return setting_value
        else:
            # Convert to array using split pattern
            try:
                return re.split(arraypattern, setting_value)
            except TypeError:
                error_message = "{} variable cannot be split".format(setting)
                raise ImproperlyConfigured(error_message)

    else:
        return setting_value


# SECURITY WARNING: keep secret key used in production secret!
SECRET_KEY = retrieve_setting('SECRET_KEY')

# SECURITY WARNING: Do not run debug in production
DEBUG = retrieve_setting('DEBUG', boolset=True, defaultset=True, defaultval='False')

# Hosts allowed to be served by Django
ALLOWED_HOSTS = retrieve_setting('ALLOWED_HOSTS', arrayset=True, defaultset=True, defaultval=[])

# Registration mode
GUEST_REGISTRATION = retrieve_setting('GUEST_REGISTRATION', defaultset=True, defaultval='DISABLED')

# Database Settings
DB_NAME = retrieve_setting('DATABASE_NAME')
DB_USER = retrieve_setting('DATABASE_USER')
DB_PASS = retrieve_setting('DATABASE_PASS')
DB_HOST = retrieve_setting('DATABASE_HOST', defaultset=True, defaultval='127.0.0.1')
DB_PORT = retrieve_setting('DATABASE_PORT', defaultset=True, defaultval='5432')

WSGI_APPLICATION = 'YaraGuardian.wsgi.application'
ROOT_URLCONF = 'YaraGuardian.urls'
AUTH_USER_MODEL = 'core.User'
LOGIN_URL = '/login/'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR.child("static")

STATICFILES_DIRS = [BASE_DIR.child('stylesheets'),
                    BASE_DIR.child('angular_app'),
                    BASE_DIR.child('npm')]

# Ensure static file directories exist
for DIRECTORY in STATICFILES_DIRS:
    DIRECTORY.mkdir()

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',

    # Add djangorestframework
    'rest_framework',

    # Add Token Authentication
    'rest_framework.authtoken',

    # Add django-angular
    'djng',

    # Add DRF Docs
    'rest_framework_docs',

    # Application components
    'core',
    'rules'
]

MIDDLEWARE_CLASSES = [
    # Add Angular URL Middleware
    'djng.middleware.AngularUrlMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEMPLATE_ROOT],
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

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASS,
        'HOST': DB_HOST,
        'PORT': DB_PORT,
    }
}

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

# REST Framework default configurations
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

# Logging Configurations
LOGGING_FILE = os.path.join(LOGGING_ROOT, 'manager.log')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOGGING_FILE,
        },
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'YaraGuardian.core.signals': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

if DEBUG:
    # Switch loggers to DEBUG mode
    for logger_name, logger_attrs in LOGGING['loggers'].items():
        logger_attrs['level'] = 'DEBUG'
        logger_attrs['handlers'] = ['console']

    # Use fake mail backend for debugging
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

else:
    # Email Settings
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST_USER = retrieve_setting('EMAIL_USER')
    EMAIL_HOST_PASSWORD = retrieve_setting('EMAIL_PASSWORD')
    EMAIL_USE_TLS = retrieve_setting('EMAIL_USE_TLS', boolset=True, defaultset=True, defaultval='True')
    EMAIL_HOST = retrieve_setting('EMAIL_HOST', defaultset=True, defaultval='smtp.gmail.com')
    EMAIL_PORT = retrieve_setting('EMAIL_PORT', defaultset=True, defaultval='587')

# Social Authentication Configurations
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = retrieve_setting('GOOGLE_OAUTH2_KEY', defaultset=True, defaultval=None)
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = retrieve_setting('GOOGLE_OAUTH2_SECRET', defaultset=True, defaultval=None)

if SOCIAL_AUTH_GOOGLE_OAUTH2_KEY and SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET:
    # Add Social Django Support
    INSTALLED_APPS += ['social_django']

    SOCIAL_AUTH_USER_MODEL = 'core.User'
    SOCIAL_AUTH_URL_NAMESPACE = 'social'
    SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'

    # Add Social Django Template Processors
    TEMPLATES[0]['OPTIONS']['context_processors'] += ['social_django.context_processors.backends',
                                                      'social_django.context_processors.login_redirect']

    # Specify Authentication Providers to support Social Django backends
    AUTHENTICATION_BACKENDS = (
        # Social Django
        'social_core.backends.google.GoogleOAuth2',
        # Django
        'django.contrib.auth.backends.ModelBackend',
    )

    # Force headers to HTTPS when behind a reverse proxy
    SOCIAL_AUTH_REDIRECT_IS_HTTPS = retrieve_setting('REDIRECT_HTTPS', boolset=True, defaultset=True, defaultval='False')

    SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = retrieve_setting('GOOGLE_WHITELISTED_DOMAINS',
                                                                     arrayset=True, defaultset=True, defaultval=[])

    SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = retrieve_setting('GOOGLE_WHITELISTED_EMAILS',
                                                                    arrayset=True, defaultset=True, defaultval=[])

REST_FRAMEWORK_DOCS = {
    'HIDE_DOCS': retrieve_setting('HIDE_API_DOCS', boolset=True, defaultset=True, defaultval='False')
}

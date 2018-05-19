import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "YaraGuardian.settings")

from django.core.wsgi import get_wsgi_application
from whitenoise import WhiteNoise
from django.conf import settings

application = get_wsgi_application()

if settings.SERVE_STATIC:
    application = WhiteNoise(application)

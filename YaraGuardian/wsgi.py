import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "YaraGuardian.settings")

from django.core.wsgi import get_wsgi_application
from whitenoise.django import DjangoWhiteNoise
from django.conf import settings

if settings.SERVE_STATIC:
    application = DjangoWhiteNoise(get_wsgi_application())
else:
    application = get_wsgi_application()

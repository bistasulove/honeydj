import environ

from .base import *  # noqa: F401, F403
from .base import BASE_DIR

env = environ.Env()

# Read .env file when running locally outside Docker
environ.Env.read_env(BASE_DIR / ".env")

DEBUG = True
ALLOWED_HOSTS = ["*"]

# Synchronous DB driver is fine locally; async uses psycopg
DATABASES["default"]["CONN_MAX_AGE"] = 0  # noqa: F405

# Django Debug Toolbar — install separately if desired
INTERNAL_IPS = ["127.0.0.1"]

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "honeydj.settings.local")

app = Celery("honeydj")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

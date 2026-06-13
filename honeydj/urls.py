from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Admin is mounted at an obscured, env-configured suffix (e.g. /hd-console/)
    # so it is not discoverable at the default /admin/ on a honeypot host.
    path(f"hd-{settings.ADMIN_URL_SUFFIX}/", admin.site.urls),
    path("api/events/", include("apps.events.urls", namespace="events")),
    path("api/feeds/", include("apps.feeds.urls", namespace="feeds")),
    path("dashboard/", include("apps.dashboard.urls", namespace="dashboard")),
    # Decoy views are mounted last, at the site root, so their well-known
    # attack paths (/.env, /wp-admin/, …) look authentic. Keep this last so it
    # never shadows the real prefixes above.
    path("", include("apps.honeypot.urls", namespace="honeypot")),
]

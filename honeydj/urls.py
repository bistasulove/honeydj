from django.conf import settings
from django.contrib import admin
from django.urls import include, path

_ADMIN_PREFIX = f"hd-{settings.ADMIN_URL_SUFFIX}/"

urlpatterns = [
    # The dashboard lives behind the obscured admin prefix (e.g.
    # /hd-console/dashboard/) so it shares the admin's auth and isn't reachable
    # from a guessable path. Listed before admin.site.urls so its longer prefix
    # is matched first.
    path(
        f"{_ADMIN_PREFIX}dashboard/",
        include("apps.dashboard.urls", namespace="dashboard"),
    ),
    # Admin is mounted at an obscured, env-configured suffix (e.g. /hd-console/)
    # so it is not discoverable at the default /admin/ on a honeypot host.
    path(_ADMIN_PREFIX, admin.site.urls),
    path("api/events/", include("apps.events.urls", namespace="events")),
    path("api/feeds/", include("apps.feeds.urls", namespace="feeds")),
    # Decoy views are mounted last, at the site root, so their well-known
    # attack paths (/.env, /wp-admin/, …) look authentic. Keep this last so it
    # never shadows the real prefixes above.
    path("", include("apps.honeypot.urls", namespace="honeypot")),
]

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/events/", include("apps.events.urls", namespace="events")),
    path("api/feeds/", include("apps.feeds.urls", namespace="feeds")),
    path("dashboard/", include("apps.dashboard.urls", namespace="dashboard")),
    # Decoy views are mounted last, at the site root, so their well-known
    # attack paths (/.env, /wp-admin/, …) look authentic. Keep this last so it
    # never shadows the real prefixes above.
    path("", include("apps.honeypot.urls", namespace="honeypot")),
]

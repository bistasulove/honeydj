from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/honeypot/", include("apps.honeypot.urls", namespace="honeypot")),
    path("api/events/", include("apps.events.urls", namespace="events")),
    path("api/feeds/", include("apps.feeds.urls", namespace="feeds")),
    path("dashboard/", include("apps.dashboard.urls", namespace="dashboard")),
]

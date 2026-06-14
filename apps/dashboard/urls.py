from django.urls import URLPattern, URLResolver, path

from apps.dashboard.views import DashboardView, MapDataView, StatsView

app_name = "dashboard"

urlpatterns: list[URLPattern | URLResolver] = [
    path("", DashboardView.as_view(), name="map"),
    path("map-data/", MapDataView.as_view(), name="map_data"),
    path("stats/", StatsView.as_view(), name="stats"),
]

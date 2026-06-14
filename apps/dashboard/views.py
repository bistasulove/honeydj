"""Dashboard views for the honeypot intelligence console.

These power the real-time Leaflet attack map embedded in the (unfold) admin:

* ``MapDataView`` serves geolocated attacker profiles as GeoJSON, cached briefly
  so the map's 30-second polling never hammers the database.
* ``DashboardView`` renders the map page with a few headline counters.

Both require an authenticated admin session — they sit behind the obscured admin
URL prefix (see ``honeydj/urls.py``) and redirect to the admin login otherwise.
"""

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.db.models import Count
from django.http import HttpRequest, JsonResponse
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import TemplateView

from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile

# Cap the map payload so a busy honeypot can't return tens of thousands of
# points; the most recently active attackers are the interesting ones.
MAP_PROFILE_LIMIT = 500
MAP_CACHE_KEY = "dashboard:map_data"
MAP_CACHE_TTL = 30  # seconds — matches the client's poll interval

# How many recent events to seed the live table with on page load. Matches the
# client-side cap (data-max-rows) so a refresh shows the same window the live
# stream would have built up to.
LIVE_TABLE_LIMIT = 50


class MapDataView(LoginRequiredMixin, View):
    """Return the last 500 geolocated attacker profiles as GeoJSON.

    Profiles without coordinates (GeoIP miss) are excluded — they have nowhere
    to plot. The serialised FeatureCollection is cached for 30 seconds so
    repeated polls from open dashboards share one query.
    """

    login_url = reverse_lazy("admin:login")

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        payload = cache.get(MAP_CACHE_KEY)
        if payload is None:
            payload = self._build_geojson()
            cache.set(MAP_CACHE_KEY, payload, MAP_CACHE_TTL)
        return JsonResponse(payload)

    @staticmethod
    def _build_geojson() -> dict[str, Any]:
        profiles = (
            AttackerProfile.objects.exclude(lat__isnull=True)
            .exclude(lon__isnull=True)
            .order_by("-last_seen")[:MAP_PROFILE_LIMIT]
        )
        features: list[dict[str, Any]] = []
        for profile in profiles:
            # The query already excludes null coordinates; this guard re-states
            # that for the type checker (lat/lon are Optional on the model).
            if profile.lat is None or profile.lon is None:
                continue
            features.append(
                {
                    "type": "Feature",
                    "geometry": {
                        # GeoJSON is [longitude, latitude] — easy to transpose.
                        "type": "Point",
                        "coordinates": [float(profile.lon), float(profile.lat)],
                    },
                    "properties": {
                        "ip": profile.ip,
                        "country": profile.country,
                        "city": profile.city,
                        "threat_score": profile.threat_score,
                        "event_count": profile.event_count,
                        "last_seen": profile.last_seen.isoformat(),
                        "tags": profile.tags,
                    },
                }
            )
        return {"type": "FeatureCollection", "features": features}


def _headline_context() -> dict[str, Any]:
    """Build the headline counter strip shown by both the full page and the poll.

    Shared by ``DashboardView`` (full page load) and ``StatsView`` (the HTMX
    poll) so the numbers are computed in exactly one place.
    """
    top_decoys = (
        HoneyEvent.objects.values("decoy_type")
        .annotate(hits=Count("id"))
        .order_by("-hits")[:5]
    )
    return {
        "total_events": HoneyEvent.objects.count(),
        "unique_attackers": AttackerProfile.objects.count(),
        "top_decoys": list(top_decoys),
    }


class DashboardView(LoginRequiredMixin, TemplateView):
    """Render the live attack map with a few headline counters."""

    login_url = reverse_lazy("admin:login")
    template_name = "dashboard/map.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context.update(_headline_context())
        # Seed the live table with the most recent enriched events so a page
        # refresh isn't blank — the WebSocket stream prepends newer ones on top.
        # select_related pulls each event's attacker in one join (no N+1) for the
        # country/threat/tags columns, which live on the profile.
        context["recent_events"] = (
            HoneyEvent.objects.filter(enriched=True)
            .select_related("attacker")
            .order_by("-timestamp")[:LIVE_TABLE_LIMIT]
        )
        return context


class StatsView(LoginRequiredMixin, TemplateView):
    """Render just the headline counter strip for HTMX auto-refresh.

    The ``_stats.html`` partial polls this endpoint (``hx-trigger="every 10s"``)
    and swaps itself with the response, so the counters stay live without a full
    page reload. The partial's root element re-declares the poll, so each swapped
    response keeps the cycle going.
    """

    login_url = reverse_lazy("admin:login")
    template_name = "dashboard/partials/_stats.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context.update(_headline_context())
        return context

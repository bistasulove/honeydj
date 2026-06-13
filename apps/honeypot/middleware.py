"""HoneyMiddleware — intercepts requests to decoy routes.

Sits directly below SecurityMiddleware. The hot path does no network or
external blocking I/O: route matching reads an in-process cache, and the only
synchronous DB work is the single HoneyEvent insert (per architecture.md).
Enrichment (GeoIP, AttackerProfile, AbuseIPDB, TTP, WebSocket push) is handed
off to the enrich_event Celery task.

Rendering and event capture are shared with the explicit decoy views via
apps/honeypot/decoys.py, so a request caught here is logged and answered
identically to one routed straight to a view. Because middleware runs before
URL resolution, a path matched by a DecoyRoute never reaches a view, so there
is no double capture.
"""

import logging
import re
from datetime import datetime

from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from apps.events.tasks import enrich_event
from apps.honeypot.decoys import (
    MAX_BODY_BYTES as MAX_BODY_BYTES,  # re-exported for tests/callers
    RATE_LIMIT_MAX as RATE_LIMIT_MAX,  # re-exported for tests/callers
    capture_event,
    client_ip,
    render_decoy,
)
from apps.honeypot.models import DecoyRoute

logger = logging.getLogger(__name__)

# --- Route cache (module-level, in-process) -------------------------------
_route_cache: list[DecoyRoute] = []
_regex_cache: dict[int, re.Pattern[str]] = {}
_cache_loaded_at: datetime | None = None
CACHE_TTL = 60  # seconds


def invalidate_route_cache(*args: object, **kwargs: object) -> None:
    """Force a reload on the next request. Wired to DecoyRoute save/delete signals."""
    global _cache_loaded_at
    _cache_loaded_at = None


def _load_routes() -> None:
    """Reload active routes from the DB (one query) and precompile regex patterns."""
    global _route_cache, _regex_cache, _cache_loaded_at
    routes = list(DecoyRoute.objects.filter(is_active=True).order_by("-priority", "path_pattern"))
    compiled: dict[int, re.Pattern[str]] = {}
    for route in routes:
        if route.is_regex:
            try:
                compiled[route.pk] = re.compile(route.path_pattern)
            except re.error:
                logger.warning(
                    "Skipping DecoyRoute %s: invalid regex %r", route.pk, route.path_pattern
                )
    _route_cache = routes
    _regex_cache = compiled
    _cache_loaded_at = timezone.now()


def _get_routes() -> list[DecoyRoute]:
    if (
        _cache_loaded_at is None
        or (timezone.now() - _cache_loaded_at).total_seconds() > CACHE_TTL
    ):
        _load_routes()
    return _route_cache


def _match_route(path: str) -> DecoyRoute | None:
    """Exact (non-regex) matches first, then regex. Highest priority wins within each pass."""
    routes = _get_routes()
    for route in routes:
        if not route.is_regex and route.path_pattern == path:
            return route
    for route in routes:
        if route.is_regex:
            pattern = _regex_cache.get(route.pk)
            if pattern is not None and pattern.search(path):
                return route
    return None


class HoneyMiddleware:
    """Capture requests hitting decoy routes; pass everything else through."""

    def __init__(self, get_response: object) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        route = _match_route(request.path)
        if route is None:
            return self.get_response(request)  # type: ignore[operator,no-any-return]
        return self._handle_decoy(request, route)

    def _handle_decoy(self, request: HttpRequest, route: DecoyRoute) -> HttpResponse:
        event = capture_event(request, route.decoy_type)
        if event is None:
            logger.warning(
                "Rate limit exceeded for %s on %s — skipping event capture",
                client_ip(request),
                request.path,
            )
        else:
            enrich_event.delay(event.id)
        return render_decoy(route.decoy_type)

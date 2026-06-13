import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from apps.events.models import HoneyEvent
from apps.honeypot import middleware
from apps.honeypot.middleware import HoneyMiddleware
from apps.honeypot.models import DecoyRoute
from tests.factories import DecoyRouteFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def dispatched(monkeypatch):
    """Capture enrich_event.delay calls instead of hitting the broker."""
    calls: list[int] = []
    monkeypatch.setattr(middleware.enrich_event, "delay", calls.append)
    return calls


@pytest.fixture
def get_response():
    """A sentinel downstream handler so we can detect pass-through."""
    def _handler(request):
        return HttpResponse("REAL_VIEW", status=200)

    return _handler


def make_mw(get_response):
    return HoneyMiddleware(get_response)


# --- decoy hit ------------------------------------------------------------


def test_decoy_hit_captures_event_and_dispatches(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/", decoy_type=DecoyRoute.DecoyType.ADMIN)
    mw = make_mw(get_response)

    request = rf.get("/admin/", HTTP_USER_AGENT="sqlmap/1.7")
    response = mw(request)

    assert response.status_code == 200
    assert b"Django administration" in response.content
    assert response["Server"]
    assert response["X-Powered-By"]
    assert response.content != b"REAL_VIEW"  # downstream view was NOT called

    event = HoneyEvent.objects.get()
    assert event.path == "/admin/"
    assert event.method == "GET"
    assert event.decoy_type == DecoyRoute.DecoyType.ADMIN
    assert event.user_agent == "sqlmap/1.7"
    assert dispatched == [event.id]


def test_decoy_hit_strips_sensitive_headers(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/")
    mw = make_mw(get_response)

    request = rf.get(
        "/admin/",
        HTTP_COOKIE="sessionid=secret",
        HTTP_AUTHORIZATION="Bearer token123",
        HTTP_X_CUSTOM="keepme",
    )
    mw(request)

    headers = HoneyEvent.objects.get().headers
    lowered = {k.lower() for k in headers}
    assert "cookie" not in lowered
    assert "authorization" not in lowered
    assert headers.get("X-Custom") == "keepme"


def test_decoy_hit_captures_ja3_and_truncates_body(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/api/debug")
    mw = make_mw(get_response)

    big = "A" * (middleware.MAX_BODY_BYTES + 5000)
    request = rf.post(
        "/api/debug",
        data=big,
        content_type="text/plain",
        HTTP_X_JA3_HASH="769,47-53,0-10-11,23-24,0",
    )
    mw(request)

    event = HoneyEvent.objects.get()
    assert event.ja3_hash == "769,47-53,0-10-11,23-24,0"
    assert len(event.body.encode("utf-8")) == middleware.MAX_BODY_BYTES


def test_client_ip_prefers_forwarded_for(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/")
    mw = make_mw(get_response)

    request = rf.get("/admin/", HTTP_X_FORWARDED_FOR="203.0.113.7, 10.0.0.1")
    mw(request)

    assert HoneyEvent.objects.get().ip == "203.0.113.7"


# --- non-decoy pass-through -----------------------------------------------


def test_non_decoy_passes_through(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/")
    mw = make_mw(get_response)

    request = rf.get("/totally/legit/page")
    response = mw(request)

    assert response.content == b"REAL_VIEW"
    assert response.status_code == 200
    assert not HoneyEvent.objects.exists()
    assert dispatched == []


def test_inactive_route_is_ignored(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/", is_active=False)
    mw = make_mw(get_response)

    response = mw(rf.get("/admin/"))

    assert response.content == b"REAL_VIEW"
    assert not HoneyEvent.objects.exists()


# --- rate-limit trigger ---------------------------------------------------


def test_rate_limit_caps_stored_events(rf, get_response, dispatched, monkeypatch):
    DecoyRouteFactory(path_pattern="/admin/")
    mw = make_mw(get_response)

    # Spy on the warning rather than relying on the "apps" logger's propagate=False config.
    warnings: list[str] = []
    monkeypatch.setattr(
        middleware.logger, "warning", lambda msg, *args: warnings.append(msg % args)
    )

    responses = [
        mw(rf.get("/admin/", REMOTE_ADDR="198.51.100.5"))
        for _ in range(middleware.RATE_LIMIT_MAX + 5)
    ]

    # Only the cap is stored, but every probe still gets a convincing response.
    assert HoneyEvent.objects.filter(ip="198.51.100.5").count() == middleware.RATE_LIMIT_MAX
    assert all(r.status_code == 200 for r in responses)
    assert all(b"REAL_VIEW" not in r.content for r in responses)
    assert sum("Rate limit exceeded" in w for w in warnings) == 5
    # Dispatch happens only for stored events.
    assert len(dispatched) == middleware.RATE_LIMIT_MAX


def test_rate_limit_is_per_ip(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="/admin/")
    mw = make_mw(get_response)

    for _ in range(middleware.RATE_LIMIT_MAX + 2):
        mw(rf.get("/admin/", REMOTE_ADDR="198.51.100.5"))
    mw(rf.get("/admin/", REMOTE_ADDR="198.51.100.99"))

    assert HoneyEvent.objects.filter(ip="198.51.100.5").count() == middleware.RATE_LIMIT_MAX
    assert HoneyEvent.objects.filter(ip="198.51.100.99").count() == 1


# --- route matching: exact vs regex, precedence ---------------------------


def test_regex_route_matches(rf, get_response, dispatched):
    DecoyRouteFactory(
        path_pattern=r"^/wp-admin/.*",
        is_regex=True,
        decoy_type=DecoyRoute.DecoyType.WP_ADMIN,
    )
    mw = make_mw(get_response)

    response = mw(rf.get("/wp-admin/setup-config.php"))

    assert HoneyEvent.objects.get().decoy_type == DecoyRoute.DecoyType.WP_ADMIN
    assert b"wp-login.php" in response.content


def test_exact_match_wins_over_regex(rf, get_response, dispatched):
    DecoyRouteFactory(
        path_pattern=r"^/api/.*",
        is_regex=True,
        decoy_type=DecoyRoute.DecoyType.API,
        priority=100,
    )
    DecoyRouteFactory(
        path_pattern="/api/users",
        is_regex=False,
        decoy_type=DecoyRoute.DecoyType.ADMIN,
        priority=1,
    )
    mw = make_mw(get_response)

    mw(rf.get("/api/users"))

    # Exact (non-regex) pass runs first, even though the regex route has higher priority.
    assert HoneyEvent.objects.get().decoy_type == DecoyRoute.DecoyType.ADMIN


def test_invalid_regex_is_skipped(rf, get_response, dispatched):
    DecoyRouteFactory(path_pattern="([unclosed", is_regex=True)
    mw = make_mw(get_response)

    response = mw(rf.get("/anything"))

    assert response.content == b"REAL_VIEW"
    assert not HoneyEvent.objects.exists()


# --- cache invalidation ---------------------------------------------------


def test_signal_invalidates_cache(rf, get_response, dispatched):
    mw = make_mw(get_response)

    # Prime the cache with no matching routes.
    assert mw(rf.get("/secret-panel")).content == b"REAL_VIEW"

    # Creating a route fires post_save -> invalidate; next request reloads.
    DecoyRouteFactory(path_pattern="/secret-panel", decoy_type=DecoyRoute.DecoyType.ADMIN)
    response = mw(rf.get("/secret-panel"))

    assert response.content != b"REAL_VIEW"
    assert HoneyEvent.objects.filter(path="/secret-panel").exists()


def test_stale_cache_reloads_after_ttl(rf, get_response, dispatched, monkeypatch):
    mw = make_mw(get_response)
    assert mw(rf.get("/late-route")).content == b"REAL_VIEW"

    # Add a route directly via the manager (bypass signals) to prove TTL reload.
    DecoyRoute.objects.create(
        path_pattern="/late-route",
        decoy_type=DecoyRoute.DecoyType.ADMIN,
        response_template="default",
    )
    middleware._cache_loaded_at = None  # simulate TTL expiry

    response = mw(rf.get("/late-route"))
    assert response.content != b"REAL_VIEW"

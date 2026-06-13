import pytest
from django.test import RequestFactory
from django.urls import reverse

from apps.events.models import HoneyEvent
from apps.honeypot import decoys, views
from apps.honeypot.models import DecoyRoute

pytestmark = pytest.mark.django_db


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def dispatched(monkeypatch):
    """Capture enrich_event.delay calls instead of hitting the broker."""
    calls: list[int] = []
    monkeypatch.setattr(views.enrich_event, "delay", calls.append)
    return calls


# --- per-view rendering + capture -----------------------------------------


@pytest.mark.parametrize(
    ("view_cls", "decoy_type", "needle", "content_type"),
    [
        (views.FakeAdminView, DecoyRoute.DecoyType.ADMIN, b"Django administration", "text/html"),
        (views.FakeDotEnvView, DecoyRoute.DecoyType.ENV, b"DB_PASSWORD", "text/plain"),
        (views.FakeWpAdminView, DecoyRoute.DecoyType.WP_ADMIN, b"wp-login.php", "text/html"),
        (views.FakeApiDebugView, DecoyRoute.DecoyType.API, b"Traceback", "application/json"),
    ],
)
def test_view_renders_and_logs(rf, dispatched, view_cls, decoy_type, needle, content_type):
    request = rf.get("/decoy-path", HTTP_USER_AGENT="sqlmap/1.7")
    response = view_cls.as_view()(request)

    # Convincing response, never a 404, with realistic server headers.
    assert response.status_code in (200, 500)
    assert needle in response.content
    assert response["Content-Type"].startswith(content_type)
    assert response["Server"]
    assert response["X-Powered-By"]

    event = HoneyEvent.objects.get()
    assert event.decoy_type == decoy_type
    assert event.path == "/decoy-path"
    assert event.user_agent == "sqlmap/1.7"
    assert dispatched == [event.id]


def test_api_debug_returns_500(rf, dispatched):
    response = views.FakeApiDebugView.as_view()(rf.get("/api/debug/"))
    assert response.status_code == 500


def test_view_captures_post_body_and_strips_sensitive_headers(rf, dispatched):
    request = rf.post(
        "/wp-login.php",
        data="log=admin&pwd=hunter2",
        content_type="application/x-www-form-urlencoded",
        HTTP_COOKIE="sessionid=secret",
        HTTP_AUTHORIZATION="Bearer token123",
        HTTP_X_CUSTOM="keepme",
    )
    views.FakeWpAdminView.as_view()(request)

    event = HoneyEvent.objects.get()
    assert event.method == "POST"
    assert "log=admin&pwd=hunter2" in event.body
    lowered = {k.lower() for k in event.headers}
    assert "cookie" not in lowered
    assert "authorization" not in lowered
    assert event.headers.get("X-Custom") == "keepme"


def test_view_respects_rate_limit(rf, dispatched, monkeypatch):
    warnings: list[str] = []
    monkeypatch.setattr(views.logger, "warning", lambda msg, *args: warnings.append(msg % args))

    responses = [
        views.FakeDotEnvView.as_view()(rf.get("/.env", REMOTE_ADDR="198.51.100.5"))
        for _ in range(decoys.RATE_LIMIT_MAX + 3)
    ]

    # Only the cap is stored, but every probe still gets a convincing response.
    assert HoneyEvent.objects.count() == decoys.RATE_LIMIT_MAX
    assert all(b"DB_PASSWORD" in r.content for r in responses)
    assert sum("Rate limit exceeded" in w for w in warnings) == 3
    # Enrichment is dispatched only for stored events.
    assert len(dispatched) == decoys.RATE_LIMIT_MAX


# --- URL wiring -----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected_path"),
    [
        ("honeypot:fake_env", "/.env"),
        ("honeypot:fake_wp_admin", "/wp-admin/"),
        ("honeypot:fake_wp_login", "/wp-login.php"),
        ("honeypot:fake_admin", "/administrator/"),
        ("honeypot:fake_api_debug", "/api/debug/"),
    ],
)
def test_decoy_urls_resolve_at_root(name, expected_path):
    assert reverse(name) == expected_path


def test_url_routed_request_logs_event(client, dispatched):
    """End-to-end: a request through the URL conf (and middleware) logs once."""
    response = client.get("/.env")

    assert response.status_code == 200
    assert b"DB_PASSWORD" in response.content
    event = HoneyEvent.objects.get()
    assert event.decoy_type == DecoyRoute.DecoyType.ENV
    assert event.path == "/.env"
    assert dispatched == [event.id]

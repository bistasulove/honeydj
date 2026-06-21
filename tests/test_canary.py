import uuid

import pytest
from django.test import Client, RequestFactory
from django.urls import reverse

from apps.events.models import HoneyEvent
from apps.honeypot import canary
from apps.honeypot.models import CanaryToken
from tests.factories import CanaryTokenFactory, UserFactory

pytestmark = pytest.mark.django_db


# A 1×1 transparent GIF starts with the GIF89a magic header.
_GIF_MAGIC = b"GIF89a"


@pytest.fixture
def dispatched(monkeypatch):
    """Capture enrich_event.delay calls instead of hitting the broker."""
    calls: list[int] = []
    monkeypatch.setattr(canary.enrich_event, "delay", calls.append)
    return calls


def _ping_url(token: CanaryToken) -> str:
    return reverse("honeypot:canary_ping", args=[token.token_id])


# --- ping endpoint: trip behaviour ----------------------------------------


def test_ping_trips_token_and_logs_event(dispatched):
    """First hit stamps the token, logs a canary event, and dispatches enrichment."""
    token = CanaryTokenFactory()
    response = Client().get(_ping_url(token), REMOTE_ADDR="203.0.113.7")

    assert response.status_code == 200
    assert response["Content-Type"] == "image/gif"
    assert response.content.startswith(_GIF_MAGIC)

    token.refresh_from_db()
    assert token.triggered is True
    assert token.triggered_at is not None
    assert token.trigger_ip == "203.0.113.7"

    event = HoneyEvent.objects.get()
    assert event.decoy_type == HoneyEvent.DecoyType.CANARY
    assert event.ip == "203.0.113.7"
    assert dispatched == [event.id]


def test_second_ping_does_not_duplicate_event(dispatched):
    """A token only fires once: the second hit logs nothing and re-dispatches nothing."""
    token = CanaryTokenFactory()
    url = _ping_url(token)
    client = Client()

    first = client.get(url)
    second = client.get(url)

    # Both return the pixel — the trip-wire never reveals it has already fired.
    assert first.status_code == second.status_code == 200
    assert second.content.startswith(_GIF_MAGIC)
    assert HoneyEvent.objects.count() == 1
    assert len(dispatched) == 1


def test_ping_works_unauthenticated_and_returns_pixel(dispatched):
    """No auth required — an attacker must be able to trip the wire."""
    token = CanaryTokenFactory()
    # A fresh client with no session/login.
    response = Client().get(_ping_url(token))

    assert response.status_code == 200
    assert response["Content-Type"] == "image/gif"
    assert response.content.startswith(_GIF_MAGIC)


def test_ping_post_also_trips(dispatched):
    """Attackers may POST; the wire trips on any method, CSRF-exempt."""
    token = CanaryTokenFactory()
    csrf_client = Client(enforce_csrf_checks=True)
    response = csrf_client.post(_ping_url(token), data={"x": "1"})

    assert response.status_code == 200
    token.refresh_from_db()
    assert token.triggered is True
    assert HoneyEvent.objects.count() == 1


def test_unknown_token_returns_404(dispatched):
    """A token UUID with no row is a dead URL — 404, nothing logged."""
    response = Client().get(reverse("honeypot:canary_ping", args=[uuid.uuid4()]))

    assert response.status_code == 404
    assert HoneyEvent.objects.count() == 0
    assert dispatched == []


def test_malformed_uuid_does_not_resolve(dispatched):
    """The <uuid:…> converter rejects a non-UUID path outright (404)."""
    response = Client().get("/canary/not-a-uuid/ping/")

    assert response.status_code == 404
    assert HoneyEvent.objects.count() == 0


# --- canary helpers --------------------------------------------------------


def test_generate_url_token_creates_url_token():
    user = UserFactory()
    token = canary.generate_url_token("leaked-creds.txt", user)

    assert token.token_type == CanaryToken.TokenType.URL
    assert token.label == "leaked-creds.txt"
    assert token.created_by == user
    assert token.triggered is False


def test_get_canary_url_is_absolute():
    token = CanaryTokenFactory()
    request = RequestFactory().get("/", HTTP_HOST="honeypot.example.com")
    url = canary.get_canary_url(token, request)

    assert url == f"http://honeypot.example.com/canary/{token.token_id}/ping/"


# --- create view (operator-facing) ----------------------------------------


def test_create_view_requires_login():
    """Anonymous users are redirected to the admin login, not served the form."""
    response = Client().get(reverse("honeypot:canary_create"))
    assert response.status_code == 302
    assert reverse("admin:login") in response["Location"]


def test_create_view_post_mints_token():
    user = UserFactory(is_staff=True)
    client = Client()
    client.force_login(user)

    response = client.post(
        reverse("honeypot:canary_create"),
        data={"label": "fake-aws-keys", "token_type": "url"},
    )

    assert response.status_code == 201
    body = response.json()
    token = CanaryToken.objects.get(label="fake-aws-keys")
    assert body["token_id"] == str(token.token_id)
    assert body["ping_url"].endswith(f"/canary/{token.token_id}/ping/")
    assert token.created_by == user


def test_create_view_rejects_blank_label():
    user = UserFactory(is_staff=True)
    client = Client()
    client.force_login(user)

    response = client.post(reverse("honeypot:canary_create"), data={"label": "  "})

    assert response.status_code == 400
    assert CanaryToken.objects.count() == 0

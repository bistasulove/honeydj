"""Tests for the simulate_scanner management command.

The command drives a forged request through HoneyMiddleware and (by default)
enriches inline, so these assert the full capture → enrich outcome. The route
cache and rate-limit cache are reset per test by tests/conftest.py.
"""

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.events.models import HoneyEvent
from apps.honeypot.models import DecoyRoute
from apps.profiles.models import AttackerProfile

pytestmark = pytest.mark.django_db

KNOWN_JA3 = "5d65ea3fb1d4aa7d826733d2f2cbbb1d"  # meterpreter, in KNOWN_SCANNER_JA3


@pytest.fixture
def no_geo(monkeypatch):
    monkeypatch.setattr("apps.events.tasks.geoip_lookup", lambda ip: {})


@pytest.fixture(autouse=True)
def no_api_key(settings):
    settings.ABUSEIPDB_API_KEY = ""
    settings.KNOWN_SCANNER_JA3 = []


def run(*args: str) -> str:
    out = StringIO()
    call_command("simulate_scanner", *args, stdout=out)
    return out.getvalue()


def test_default_run_captures_and_enriches(no_geo):
    run("--ip", "203.0.113.50")

    event = HoneyEvent.objects.get(ip="203.0.113.50")
    assert event.ja3_hash == KNOWN_JA3
    assert event.tags == ["sqlmap"]  # default UA

    profile = AttackerProfile.objects.get(ip="203.0.113.50")
    assert profile.is_known_scanner is True
    assert profile.threat_score == 30  # JA3 scanner match
    assert set(profile.tags) == {"meterpreter", "sqlmap"}


def test_creates_route_when_absent(no_geo):
    assert not DecoyRoute.objects.filter(path_pattern="/wp-login.php").exists()

    run("--ip", "203.0.113.51", "--path", "/wp-login.php")

    assert DecoyRoute.objects.filter(path_pattern="/wp-login.php").exists()
    assert HoneyEvent.objects.filter(path="/wp-login.php").exists()


def test_body_trips_ttp_classifier(no_geo):
    run("--ip", "203.0.113.52", "--ja3", "", "--ua", "curl/8.0", "--body", "1 OR 1=1 -- ")

    profile = AttackerProfile.objects.get(ip="203.0.113.52")
    assert profile.is_known_scanner is False  # no JA3 sent
    assert "sql_injection" in profile.tags  # from body
    assert "curl" in profile.tags  # from UA
    assert profile.threat_score == 10  # +10 sqli; UA/no-JA3 add no score


def test_unknown_ja3_not_flagged(no_geo):
    run("--ip", "203.0.113.53", "--ja3", "deadbeef", "--ua", "Mozilla/5.0")

    profile = AttackerProfile.objects.get(ip="203.0.113.53")
    assert profile.is_known_scanner is False
    assert profile.threat_score == 0
    assert profile.tags == []


def test_async_dispatches_instead_of_enriching(no_geo, monkeypatch):
    dispatched: list[int] = []
    monkeypatch.setattr("apps.events.tasks.enrich_event.delay", dispatched.append)

    output = run("--ip", "203.0.113.54", "--async")

    event = HoneyEvent.objects.get(ip="203.0.113.54")
    assert dispatched == [event.id]
    # Enrichment didn't run inline, so no profile was built by the command.
    assert not AttackerProfile.objects.filter(ip="203.0.113.54").exists()
    assert "Dispatched enrich_event to Celery" in output


def test_rate_limited_raises_command_error(no_geo):
    DecoyRoute.objects.create(
        path_pattern="/admin/", decoy_type=DecoyRoute.DecoyType.ADMIN, response_template="default"
    )
    # Exhaust the per-IP window so the next capture is dropped.
    for _ in range(60):
        HoneyEvent.objects.create(
            ip="203.0.113.55", path="/admin/", method="GET", headers={}, user_agent="x",
            decoy_type=DecoyRoute.DecoyType.ADMIN,
        )
    from apps.honeypot.decoys import over_rate_limit

    while not over_rate_limit("203.0.113.55"):
        pass

    with pytest.raises(CommandError, match="rate limited"):
        run("--ip", "203.0.113.55")

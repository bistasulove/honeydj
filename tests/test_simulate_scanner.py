"""Tests for the simulate_scanner management command.

The command drives a forged request through HoneyMiddleware and (by default)
enriches inline, so these assert the full capture → enrich outcome. The route
cache and rate-limit cache are reset per test by tests/conftest.py.
"""

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.alerts.models import AlertRule
from apps.events.models import HoneyEvent
from apps.honeypot.models import CanaryToken, DecoyRoute
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


# --- Scenario mode (no --ip) ----------------------------------------------


@pytest.fixture
def inline_pipeline(monkeypatch):
    """Run the async pipeline synchronously so the scenario is testable worker-free.

    ``enrich_event.delay`` runs the task inline (so events end up enriched and
    profiles scored), ``dispatch_alert.delay`` is captured (no real notifier), and
    GeoIP returns nothing. Returns the list of captured dispatch_alert arg-tuples.
    """
    from apps.alerts import tasks as alert_tasks
    from apps.events import tasks as event_tasks

    monkeypatch.setattr("apps.events.tasks.geoip_lookup", lambda ip: {})
    dispatched_alerts: list[tuple] = []
    monkeypatch.setattr(alert_tasks.dispatch_alert, "delay",
                        lambda *args, **kwargs: dispatched_alerts.append(args))
    monkeypatch.setattr(event_tasks.enrich_event, "delay",
                        lambda event_id: event_tasks.enrich_event(event_id))
    return dispatched_alerts


def test_scenario_covers_four_decoy_types_and_canary(inline_pipeline):
    run("--count", "15", "--settle", "0")

    assert HoneyEvent.objects.count() == 15
    decoy_types = set(HoneyEvent.objects.values_list("decoy_type", flat=True))
    assert {"admin", "env", "wpAdmin", "api", "canary"} <= decoy_types
    # 3-5 distinct source IPs.
    assert 3 <= HoneyEvent.objects.values("ip").distinct().count() <= 5


def test_scenario_trips_a_canary_token(inline_pipeline):
    run("--count", "15", "--settle", "0")

    token = CanaryToken.objects.filter(triggered=True).first()
    assert token is not None
    assert token.trigger_ip is not None
    assert HoneyEvent.objects.filter(decoy_type="canary").exists()


def test_scenario_flags_known_scanner_with_high_score(inline_pipeline):
    run("--count", "15", "--settle", "0")

    # IP_DE hits the admin (SQLi) and .env decoys with a known-scanner JA3.
    profile = AttackerProfile.objects.get(ip="185.220.101.34")
    assert profile.is_known_scanner is True
    assert "sql_injection" in profile.tags
    assert profile.threat_score >= 40  # +30 scanner JA3, +10 per TTP tag


def test_scenario_creates_demo_rules_and_fires_alerts(inline_pipeline):
    run("--count", "15", "--settle", "0")

    rules = set(AlertRule.objects.values_list("name", flat=True))
    assert "Demo: known scanner detected" in rules
    assert "Demo: canary token tripped" in rules
    # At least the known-scanner and canary rules dispatched.
    assert len(inline_pipeline) >= 2


def test_scenario_small_count_still_covers_canary(inline_pipeline):
    run("--count", "5", "--settle", "0")

    assert HoneyEvent.objects.count() == 5
    assert CanaryToken.objects.filter(triggered=True).exists()


def test_scenario_rejects_zero_count(inline_pipeline):
    with pytest.raises(CommandError, match="--count must be at least 1"):
        run("--count", "0")

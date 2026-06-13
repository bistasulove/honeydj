import pytest
import responses

from apps.events.tasks import enrich_event
from apps.feeds.adapters.abuseipdb import _CHECK_URL
from apps.feeds.models import ThreatFeedEntry
from apps.profiles.models import AttackerProfile
from tests.factories import AttackerProfileFactory, HoneyEventFactory

pytestmark = pytest.mark.django_db

# A body that matches exactly one TTP signature (sql_injection) → +10.
SQLI_BODY = "username=admin' OR 1=1 -- "


@pytest.fixture
def no_geo(monkeypatch):
    """GeoIP returns nothing — isolates tests from the MaxMind DB."""
    monkeypatch.setattr("apps.events.tasks.geoip_lookup", lambda ip: {})


@pytest.fixture(autouse=True)
def no_api_key(settings):
    """Default to AbuseIPDB disabled; tests that need it opt back in."""
    settings.ABUSEIPDB_API_KEY = ""
    settings.KNOWN_SCANNER_JA3 = []


def _abuse_payload(confidence):
    return {"data": {"abuseConfidenceScore": confidence, "totalReports": 5,
                      "countryCode": "RU", "usageType": "Data Center"}}


def test_missing_event_is_noop():
    enrich_event(999999)  # must not raise


def test_skips_already_enriched(no_geo):
    event = HoneyEventFactory(ip="203.0.113.9", attacker=None, enriched=True, body=SQLI_BODY)
    enrich_event(event.id)
    # No profile should have been created for this IP.
    assert not AttackerProfile.objects.filter(ip="203.0.113.9").exists()


def test_creates_profile_and_links_event(monkeypatch):
    monkeypatch.setattr(
        "apps.events.tasks.geoip_lookup",
        lambda ip: {"country_code": "US", "country": "United States",
                    "city": "Ashburn", "lat": 39.0, "lon": -77.5},
    )
    event = HoneyEventFactory(ip="203.0.113.10", attacker=None, path="/api/debug", body=SQLI_BODY)

    enrich_event(event.id)

    event.refresh_from_db()
    profile = AttackerProfile.objects.get(ip="203.0.113.10")
    assert event.enriched is True
    assert event.attacker_id == profile.id
    assert profile.event_count == 1
    assert profile.tags == ["sql_injection"]
    assert profile.threat_score == 10
    assert profile.country_code == "US"
    assert profile.city == "Ashburn"


def test_idempotent_on_rerun(no_geo):
    event = HoneyEventFactory(ip="203.0.113.11", attacker=None, body=SQLI_BODY)

    enrich_event(event.id)
    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.11")
    assert profile.event_count == 1
    assert profile.threat_score == 10


def test_new_tags_only_counted_once_across_events(no_geo):
    profile = AttackerProfileFactory(ip="203.0.113.12", tags=["sql_injection"], threat_score=10)
    event = HoneyEventFactory(ip="203.0.113.12", attacker=None, body=SQLI_BODY)

    enrich_event(event.id)

    profile.refresh_from_db()
    assert profile.tags == ["sql_injection"]  # not duplicated
    assert profile.threat_score == 10  # no new tag → no increment
    assert profile.event_count == 1


@responses.activate
def test_abuseipdb_adds_score_once_per_ip(no_geo, settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(responses.GET, _CHECK_URL, json=_abuse_payload(90), status=200)

    e1 = HoneyEventFactory(ip="203.0.113.13", attacker=None, body=SQLI_BODY)
    enrich_event(e1.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.13")
    assert profile.threat_score == 30  # 10 (sqli) + 20 (abuse)
    assert ThreatFeedEntry.objects.filter(
        ip="203.0.113.13", source=ThreatFeedEntry.Source.ABUSEIPDB
    ).count() == 1

    # A second event from the same IP must not award the +20 again.
    e2 = HoneyEventFactory(ip="203.0.113.13", attacker=None, body=SQLI_BODY)
    enrich_event(e2.id)
    profile.refresh_from_db()
    assert profile.threat_score == 30
    assert profile.event_count == 2
    assert ThreatFeedEntry.objects.filter(ip="203.0.113.13").count() == 1


@responses.activate
def test_abuseipdb_below_threshold_no_score(no_geo, settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(responses.GET, _CHECK_URL, json=_abuse_payload(40), status=200)

    event = HoneyEventFactory(ip="203.0.113.14", attacker=None, body=SQLI_BODY)
    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.14")
    assert profile.threat_score == 10  # only the TTP tag
    assert not ThreatFeedEntry.objects.filter(ip="203.0.113.14").exists()


def test_known_scanner_ja3(no_geo, settings):
    settings.KNOWN_SCANNER_JA3 = ["deadbeefja3"]
    event = HoneyEventFactory(ip="203.0.113.15", attacker=None, body=SQLI_BODY, ja3_hash="deadbeefja3")

    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.15")
    assert profile.is_known_scanner is True
    assert profile.threat_score == 40  # 10 (sqli) + 30 (scanner)


def test_threat_score_capped_at_100(no_geo, settings):
    settings.KNOWN_SCANNER_JA3 = ["ja3"]
    profile = AttackerProfileFactory(ip="203.0.113.16", threat_score=95, tags=[])
    event = HoneyEventFactory(ip="203.0.113.16", attacker=None, body=SQLI_BODY, ja3_hash="ja3")

    enrich_event(event.id)

    profile.refresh_from_db()
    assert profile.threat_score == 100  # 95 + 10 + 30, capped


def test_broadcast_fires_on_commit(no_geo, monkeypatch, django_capture_on_commit_callbacks):
    sent = []
    monkeypatch.setattr("apps.events.tasks._broadcast", lambda row: sent.append(row))
    event = HoneyEventFactory(ip="203.0.113.17", attacker=None, body=SQLI_BODY)

    with django_capture_on_commit_callbacks(execute=True):
        enrich_event(event.id)

    assert len(sent) == 1
    assert sent[0]["ip"] == "203.0.113.17"
    assert sent[0]["threat_score"] == 10
    assert sent[0]["tags"] == ["sql_injection"]

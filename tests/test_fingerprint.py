"""Tests for JA3 / User-Agent fingerprinting and its wiring into capture + enrich.

Lives in the top-level ``tests/`` package alongside the rest of the suite (the
repo keeps tests out of the apps; see pytest.ini / conftest.py) rather than in
``apps/honeypot/tests/``.
"""

import pytest
from django.test import RequestFactory

from apps.events.models import HoneyEvent
from apps.events.tasks import enrich_event
from apps.honeypot import middleware
from apps.honeypot.fingerprint import (
    JA3_HEADER,
    KNOWN_SCANNER_JA3,
    classify_user_agent,
    parse_ja3_header,
)
from apps.honeypot.middleware import HoneyMiddleware
from apps.honeypot.models import DecoyRoute
from apps.profiles.models import AttackerProfile
from tests.factories import DecoyRouteFactory, HoneyEventFactory

# A JA3 hash that is in the published scanner dict, plus the tool it maps to.
KNOWN_JA3 = "5d65ea3fb1d4aa7d826733d2f2cbbb1d"  # meterpreter (Salesforce JA3)
KNOWN_TOOL = "meterpreter"

# A body that matches exactly one TTP signature (sql_injection) → +10.
SQLI_BODY = "username=admin' OR 1=1 -- "


# --- parse_ja3_header -----------------------------------------------------


def test_parse_ja3_header_present():
    request = RequestFactory().get("/", **{f"HTTP_{JA3_HEADER.upper().replace('-', '_')}": KNOWN_JA3})
    assert parse_ja3_header(request) == KNOWN_JA3


def test_parse_ja3_header_absent_returns_none():
    request = RequestFactory().get("/")
    assert parse_ja3_header(request) is None


def test_parse_ja3_header_empty_returns_none():
    request = RequestFactory().get("/", HTTP_X_JA3_HASH="")
    assert parse_ja3_header(request) is None


# --- classify_user_agent --------------------------------------------------


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        ("sqlmap/1.7.2#stable (https://sqlmap.org)", "sqlmap"),
        ("Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)", "nikto"),
        ("masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "masscan"),
        ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "nmap"),
        ("Mozilla/5.0 zgrab/0.x", "zgrab"),
        ("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "nuclei"),
        ("Mozilla/4.0 (compatible; Metasploit RSPEC)", "metasploit"),
        ("python-requests/2.31.0", "python-requests"),
        ("Go-http-client/1.1", "go-http-client"),
        ("curl/7.88.1", "curl"),
    ],
)
def test_classify_user_agent_detects_each_tool(user_agent, expected):
    assert classify_user_agent(user_agent) == [expected]


def test_classify_user_agent_no_match_for_browser():
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    assert classify_user_agent(ua) == []


def test_classify_user_agent_empty_string():
    assert classify_user_agent("") == []


def test_classify_user_agent_curl_requires_version_delimiter():
    # A browser advertising "curl"-like text without the "curl/" token must not match.
    assert classify_user_agent("Mozilla/5.0 curlybrowser") == []


# --- middleware / capture wiring ------------------------------------------


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def dispatched(monkeypatch):
    """Swallow enrich_event.delay so capture tests don't touch the broker."""
    monkeypatch.setattr(middleware.enrich_event, "delay", lambda *a, **k: None)


@pytest.mark.django_db
def test_middleware_stores_ja3_hash_on_event(rf, dispatched):
    DecoyRouteFactory(path_pattern="/admin/", decoy_type=DecoyRoute.DecoyType.ADMIN)
    mw = HoneyMiddleware(lambda request: None)

    request = rf.get("/admin/", HTTP_X_JA3_HASH=KNOWN_JA3)
    mw(request)

    event = HoneyEvent.objects.get()
    assert event.ja3_hash == KNOWN_JA3


@pytest.mark.django_db
def test_middleware_stores_user_agent_tags_on_event(rf, dispatched):
    DecoyRouteFactory(path_pattern="/admin/", decoy_type=DecoyRoute.DecoyType.ADMIN)
    mw = HoneyMiddleware(lambda request: None)

    request = rf.get("/admin/", HTTP_USER_AGENT="sqlmap/1.7")
    mw(request)

    assert HoneyEvent.objects.get().tags == ["sqlmap"]


@pytest.mark.django_db
def test_middleware_no_ja3_header_leaves_hash_null(rf, dispatched):
    DecoyRouteFactory(path_pattern="/admin/", decoy_type=DecoyRoute.DecoyType.ADMIN)
    mw = HoneyMiddleware(lambda request: None)

    mw(rf.get("/admin/", HTTP_USER_AGENT="Mozilla/5.0"))

    event = HoneyEvent.objects.get()
    assert event.ja3_hash is None
    assert event.tags == []


# --- enrich_event scanner detection ---------------------------------------


@pytest.fixture
def no_geo(monkeypatch):
    monkeypatch.setattr("apps.events.tasks.geoip_lookup", lambda ip: {})


@pytest.fixture(autouse=True)
def no_api_key(settings):
    settings.ABUSEIPDB_API_KEY = ""
    settings.KNOWN_SCANNER_JA3 = []


@pytest.mark.django_db
def test_enrich_sets_known_scanner_on_dict_hash(no_geo):
    assert KNOWN_JA3 in KNOWN_SCANNER_JA3  # guards against the fixture hash drifting
    event = HoneyEventFactory(
        ip="203.0.113.40", attacker=None, body=SQLI_BODY, ja3_hash=KNOWN_JA3, user_agent="x"
    )

    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.40")
    assert profile.is_known_scanner is True
    assert profile.threat_score == 40  # 10 (sqli) + 30 (scanner)
    # Tool name from the JA3 match is tagged, alongside the TTP tag.
    assert KNOWN_TOOL in profile.tags
    assert "sql_injection" in profile.tags


@pytest.mark.django_db
def test_enrich_unknown_ja3_not_flagged(no_geo):
    event = HoneyEventFactory(
        ip="203.0.113.41", attacker=None, body=SQLI_BODY, ja3_hash="not-a-real-hash", user_agent="x"
    )

    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.41")
    assert profile.is_known_scanner is False
    assert profile.threat_score == 10  # only the sqli tag


@pytest.mark.django_db
def test_enrich_adds_user_agent_tags_without_extra_score(no_geo):
    # UA names the tooling but isn't a JA3 match: tag added, no score beyond the TTP tag.
    event = HoneyEventFactory(
        ip="203.0.113.42",
        attacker=None,
        body=SQLI_BODY,
        ja3_hash=None,
        user_agent="sqlmap/1.7.2",
    )

    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.42")
    assert "sqlmap" in profile.tags
    assert profile.is_known_scanner is False
    assert profile.threat_score == 10  # sqli tag only; UA tags don't score


@pytest.mark.django_db
def test_enrich_known_scanner_via_settings_list(no_geo, settings):
    # Env-configured (unnamed) extension still flips the flag and awards +30.
    settings.KNOWN_SCANNER_JA3 = ["env-configured-hash"]
    event = HoneyEventFactory(
        ip="203.0.113.43", attacker=None, body=SQLI_BODY, ja3_hash="env-configured-hash", user_agent="x"
    )

    enrich_event(event.id)

    profile = AttackerProfile.objects.get(ip="203.0.113.43")
    assert profile.is_known_scanner is True
    assert profile.threat_score == 40

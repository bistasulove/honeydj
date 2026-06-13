import responses

from apps.feeds.adapters import abuseipdb
from apps.feeds.adapters.abuseipdb import _CHECK_URL, AbuseVerdict


def _payload(**overrides):
    data = {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 88,
        "totalReports": 42,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting/Transit",
    }
    data.update(overrides)
    return {"data": data}


def test_returns_none_without_api_key(settings):
    settings.ABUSEIPDB_API_KEY = ""
    assert abuseipdb.check_ip("1.2.3.4") is None


@responses.activate
def test_parses_successful_response(settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(responses.GET, _CHECK_URL, json=_payload(), status=200)

    verdict = abuseipdb.check_ip("1.2.3.4")

    assert verdict == AbuseVerdict(
        confidence=88,
        total_reports=42,
        country_code="RU",
        usage_type="Data Center/Web Hosting/Transit",
    )


@responses.activate
def test_sends_key_header_and_params(settings):
    settings.ABUSEIPDB_API_KEY = "secret-key"
    settings.ABUSEIPDB_MAX_AGE_DAYS = 90
    responses.add(responses.GET, _CHECK_URL, json=_payload(), status=200)

    abuseipdb.check_ip("9.9.9.9")

    request = responses.calls[0].request
    assert request.headers["Key"] == "secret-key"
    assert "ipAddress=9.9.9.9" in request.url
    assert "maxAgeInDays=90" in request.url


@responses.activate
def test_returns_none_on_http_error(settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(responses.GET, _CHECK_URL, status=429)

    assert abuseipdb.check_ip("1.2.3.4") is None


@responses.activate
def test_returns_none_on_malformed_json(settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(responses.GET, _CHECK_URL, json={"unexpected": True}, status=200)

    assert abuseipdb.check_ip("1.2.3.4") is None


@responses.activate
def test_missing_optional_fields_default(settings):
    settings.ABUSEIPDB_API_KEY = "test-key"
    responses.add(
        responses.GET,
        _CHECK_URL,
        json={"data": {"abuseConfidenceScore": 0}},
        status=200,
    )

    verdict = abuseipdb.check_ip("1.2.3.4")
    assert verdict == AbuseVerdict(
        confidence=0, total_reports=0, country_code=None, usage_type=None
    )

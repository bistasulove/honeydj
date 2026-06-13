"""AbuseIPDB reputation adapter.

Wraps the AbuseIPDB v2 ``/check`` endpoint. Called from the ``enrich_event``
Celery task (architecture.md step 4). Returns ``None`` when no API key is
configured or the call fails for any reason — the caller treats a ``None``
result as "no abuse data" and continues, so a flaky feed never breaks
enrichment.
"""

import logging
from dataclasses import dataclass

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@dataclass(frozen=True)
class AbuseVerdict:
    """Parsed subset of an AbuseIPDB ``/check`` response."""

    confidence: int  # abuseConfidenceScore, 0-100
    total_reports: int
    country_code: str | None
    usage_type: str | None


def check_ip(ip: str) -> AbuseVerdict | None:
    """Query AbuseIPDB for ``ip``; return a verdict or ``None`` if unavailable.

    ``None`` is returned when the API key is unset, the request fails, or the
    response is malformed. Network and parsing errors are logged and swallowed
    so enrichment can proceed without abuse data.
    """
    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        logger.debug("AbuseIPDB skipped for %s: no API key configured", ip)
        return None

    try:
        response = requests.get(
            _CHECK_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS},
            timeout=settings.ABUSEIPDB_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()["data"]
    except (requests.RequestException, ValueError, KeyError) as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None

    return AbuseVerdict(
        confidence=int(data.get("abuseConfidenceScore", 0)),
        total_reports=int(data.get("totalReports", 0)),
        country_code=data.get("countryCode"),
        usage_type=data.get("usageType"),
    )

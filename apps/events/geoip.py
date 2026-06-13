"""GeoIP lookups via a local MaxMind database.

Used by the enrich_event Celery task (architecture.md step 2), not by the
request hot path. The reader is opened once and reused; lookups are mmap-backed
local reads. Missing or unreadable databases degrade gracefully to an empty
result so enrichment never fails on geo data alone.
"""

import logging
from pathlib import Path
from typing import Any, cast

import maxminddb
from django.conf import settings

logger = logging.getLogger(__name__)

_DB_FILENAME = "GeoLite2-City.mmdb"
_reader: maxminddb.Reader | None = None
_reader_loaded = False


def _get_reader() -> maxminddb.Reader | None:
    """Open and cache the MaxMind reader, or None if the DB is unavailable."""
    global _reader, _reader_loaded
    if _reader_loaded:
        return _reader
    _reader_loaded = True
    db_path = Path(settings.GEOIP_PATH) / _DB_FILENAME
    try:
        _reader = maxminddb.open_database(str(db_path))
    except (FileNotFoundError, maxminddb.InvalidDatabaseError, OSError) as exc:
        logger.warning("GeoIP database unavailable at %s: %s", db_path, exc)
        _reader = None
    return _reader


def lookup(ip: str) -> dict[str, Any]:
    """Return geo fields for an IP, or an empty dict when no data is available."""
    reader = _get_reader()
    if reader is None:
        return {}
    try:
        record = reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError):
        return {}
    if not isinstance(record, dict):
        return {}

    data = cast(dict[str, Any], record)
    country = data.get("country") or {}
    city = data.get("city") or {}
    location = data.get("location") or {}
    return {
        "country_code": country.get("iso_code"),
        "country": country.get("names", {}).get("en"),
        "city": city.get("names", {}).get("en"),
        "lat": location.get("latitude"),
        "lon": location.get("longitude"),
    }

"""Asynchronous enrichment of captured honeypot events.

``enrich_event`` runs the pipeline described in architecture.md (steps 1-8):
load the event, geolocate the IP, look up reputation, classify TTPs, fold the
result into a single ``AttackerProfile``, mark the event enriched, and push a
compact row to connected dashboards over WebSockets.

The task is idempotent: enriching an already-enriched event is a no-op, and all
profile mutation happens inside a single locked transaction so concurrent tasks
for the same IP can't race or double-count.
"""

import logging
from datetime import timedelta

from asgiref.sync import async_to_sync
from celery import Task, shared_task
from channels.layers import get_channel_layer
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.events import ttp
from apps.events.geoip import lookup as geoip_lookup
from apps.events.models import HoneyEvent
from apps.feeds.adapters import abuseipdb
from apps.feeds.adapters.abuseipdb import AbuseVerdict
from apps.feeds.models import ThreatFeedEntry
from apps.profiles.models import AttackerProfile

logger = logging.getLogger(__name__)

# Threat-score weights (architecture.md "AttackerProfile threat score").
SCORE_PER_TTP_TAG = 10
SCORE_ABUSEIPDB = 20
SCORE_KNOWN_SCANNER = 30
ABUSEIPDB_CONFIDENCE_THRESHOLD = 50
MAX_THREAT_SCORE = 100

EVENTS_GROUP = "events"


@shared_task(bind=True, max_retries=3, queue="enrichment")  # type: ignore[misc]
def enrich_event(self: Task, event_id: int) -> None:
    """Enrich a captured honeypot event and update its attacker profile.

    Idempotent: returns early if the event is missing or already enriched.
    """
    try:
        event = HoneyEvent.objects.get(pk=event_id)
    except HoneyEvent.DoesNotExist:
        logger.warning("enrich_event: HoneyEvent %s no longer exists", event_id)
        return
    if event.enriched:
        logger.debug("enrich_event: event %s already enriched, skipping", event_id)
        return

    logger.info(
        "enrich_event: start event=%s ip=%s %s %s",
        event_id,
        event.ip,
        event.method,
        event.path,
    )

    # Network/file I/O happens outside the DB transaction so locks are held only
    # for the brief profile update, not for the duration of the HTTP call.
    geo = geoip_lookup(event.ip)
    verdict = abuseipdb.check_ip(event.ip)
    tags = ttp.classify(event.path, _body_text(event.body))
    logger.debug(
        "enrich_event: event=%s signals geo=%s abuse=%s ttp=%s",
        event_id,
        geo.get("country_code") or "none",
        f"{verdict.confidence}%" if verdict else "none",
        tags or "none",
    )

    row = _apply_enrichment(event_id, geo, verdict, tags)
    if row is None:
        # Another worker enriched it first, or the event was deleted mid-flight.
        logger.info("enrich_event: event %s already handled by another worker", event_id)
        return

    # Broadcast only after the transaction commits, so dashboards never see a
    # row that a rollback would have undone.
    transaction.on_commit(lambda: _broadcast(row))


def _body_text(body: object) -> str | None:
    """Coerce the stored JSON body to text for pattern scanning."""
    if body is None:
        return None
    return body if isinstance(body, str) else str(body)


@transaction.atomic
def _apply_enrichment(
    event_id: int,
    geo: dict[str, object],
    verdict: AbuseVerdict | None,
    tags: list[str],
) -> dict[str, object] | None:
    """Fold enrichment results into the attacker profile and mark the event done.

    Runs in a single transaction. The event and profile rows are locked with
    ``select_for_update`` so two workers enriching events from the same IP
    serialise instead of clobbering each other's score. Returns the serialised
    dashboard row, or ``None`` if the event vanished or was already enriched.
    """
    try:
        event = HoneyEvent.objects.select_for_update().get(pk=event_id)
    except HoneyEvent.DoesNotExist:
        return None
    if event.enriched:
        return None

    profile, _ = AttackerProfile.objects.select_for_update().get_or_create(ip=event.ip)

    score_delta = 0

    # +10 per genuinely new TTP tag (cumulative, deduped against existing tags).
    new_tags = [tag for tag in tags if tag not in profile.tags]
    if new_tags:
        profile.tags = profile.tags + new_tags
        score_delta += SCORE_PER_TTP_TAG * len(new_tags)

    # +20 the first time AbuseIPDB flags this IP above the confidence threshold.
    if verdict is not None and verdict.confidence > ABUSEIPDB_CONFIDENCE_THRESHOLD:
        if _record_abuse_verdict(event.ip, verdict):
            score_delta += SCORE_ABUSEIPDB

    # +30 the first time a known-scanner JA3 fingerprint is seen for this IP.
    if (
        event.ja3_hash
        and event.ja3_hash in settings.KNOWN_SCANNER_JA3
        and not profile.is_known_scanner
    ):
        profile.is_known_scanner = True
        score_delta += SCORE_KNOWN_SCANNER

    # Backfill geo/identity fields only when empty — never overwrite good data.
    _fill_geo(profile, geo)
    if verdict and not profile.country_code and verdict.country_code:
        profile.country_code = verdict.country_code

    profile.event_count += 1
    profile.threat_score = min(MAX_THREAT_SCORE, profile.threat_score + score_delta)
    profile.save()  # auto_now refreshes last_seen

    event.attacker = profile
    event.enriched = True
    event.save(update_fields=["attacker", "enriched"])

    logger.info(
        "enrich_event: done event=%s ip=%s score=%d (+%d) new_tags=%s tags=%s "
        "scanner=%s events=%d",
        event.id,
        profile.ip,
        profile.threat_score,
        score_delta,
        new_tags or "none",
        profile.tags or "none",
        profile.is_known_scanner,
        profile.event_count,
    )

    return {
        "id": event.id,
        "ip": event.ip,
        "path": event.path,
        "method": event.method,
        "decoy_type": event.decoy_type,
        "country_code": profile.country_code,
        "threat_score": profile.threat_score,
        "tags": profile.tags,
        "timestamp": event.timestamp.isoformat(),
    }


def _fill_geo(profile: AttackerProfile, geo: dict[str, object]) -> None:
    """Populate empty geo fields on the profile from a GeoIP lookup result."""
    for field in ("country_code", "country", "city", "lat", "lon"):
        value = geo.get(field)
        if value is not None and not getattr(profile, field):
            setattr(profile, field, value)


def _record_abuse_verdict(ip: str, verdict: AbuseVerdict) -> bool:
    """Upsert the AbuseIPDB verdict as a ThreatFeedEntry.

    Returns ``True`` only when this is a newly created entry, so the +20 score
    bonus is awarded once per IP rather than on every event from it.
    """
    expires_at = timezone.now() + timedelta(days=settings.THREAT_FEED_TTL_DAYS)
    _, created = ThreatFeedEntry.objects.update_or_create(
        ip=ip,
        source=ThreatFeedEntry.Source.ABUSEIPDB,
        defaults={
            "confidence": verdict.confidence,
            "category": verdict.usage_type,
            "expires_at": expires_at,
        },
    )
    return created


def _broadcast(row: dict[str, object]) -> None:
    """Push a compact enriched-event row to the dashboard WebSocket group."""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    async_to_sync(channel_layer.group_send)(
        EVENTS_GROUP,
        {"type": "event.enriched", "row": row},
    )

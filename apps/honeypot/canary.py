"""Canary tokens — single-use trip-wires planted where an attacker shouldn't look.

A canary token is a unique, innocent-looking URL you embed inside bait: a leaked
config file, a fake credentials document, an email signature, a row in a decoy
database. Nobody has a legitimate reason to fetch it, so the first request to its
ping endpoint is, by construction, evidence that the bait was opened by someone
who shouldn't have it. Each token is a row keyed by a random UUID; the ping view
(:class:`apps.honeypot.views.CanaryPingView`) looks the row up by that UUID,
stamps the first hit, logs it as a ``canary`` HoneyEvent, and returns an
invisible 1×1 pixel so the token can live inside a document or email unnoticed.

This module owns the token lifecycle: minting a URL token, building its public
ping URL, and recording the one-and-only trip. Rendering the pixel is the view's
job — everything here is request-light domain logic so it stays unit-testable.
"""

import logging

from django.contrib.auth.models import User
from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone

from apps.alerts.evaluator import evaluate_rules
from apps.events.models import HoneyEvent
from apps.events.tasks import enrich_event
from apps.honeypot import decoys
from apps.honeypot.models import CanaryToken
from apps.profiles.models import AttackerProfile

logger = logging.getLogger(__name__)


def generate_url_token(label: str, created_by: User) -> CanaryToken:
    """Mint a fresh, un-triggered URL canary token.

    ``token_id`` (the random UUID the ping URL is keyed on) is filled in by the
    model default, so callers only supply the human label and the owner.
    """
    token = CanaryToken.objects.create(
        token_type=CanaryToken.TokenType.URL,
        label=label,
        created_by=created_by,
    )
    logger.info("canary: minted url token %s (%r) by %s", token.token_id, label, created_by)
    return token


def get_canary_url(token: CanaryToken, request: HttpRequest) -> str:
    """Return the full absolute ping URL for ``token`` (``…/canary/<uuid>/ping/``).

    Built with :func:`~django.urls.reverse` so the path stays in lockstep with
    the URLconf, then made absolute against the current request's host/scheme so
    the value is safe to paste into a document or email.
    """
    path = reverse("honeypot:canary_ping", args=[token.token_id])
    return request.build_absolute_uri(path)


def record_trigger(token: CanaryToken, request: HttpRequest) -> HoneyEvent | None:
    """Record the first (and only) trip of ``token``; return the logged event.

    Claims the token with a single conditional ``UPDATE`` (``triggered=False ->
    True``) so two requests racing on the same fresh token can't both log a hit:
    exactly one update succeeds, and only that caller proceeds. A token already
    tripped — by an earlier request or the losing side of the race — returns
    ``None`` and writes nothing.

    The winning caller logs a ``canary`` HoneyEvent (never rate-limited — a trip
    is rare and high-value), hands enrichment off to Celery, and fires any alert
    rule matching ``decoy_type="canary"`` synchronously so the operator hears
    about the trip immediately rather than waiting on the enrichment queue.
    """
    ip = decoys.client_ip(request)
    claimed = CanaryToken.objects.filter(pk=token.pk, triggered=False).update(
        triggered=True,
        triggered_at=timezone.now(),
        trigger_ip=ip,
    )
    if not claimed:
        logger.debug("canary: token %s already triggered, ignoring hit", token.token_id)
        return None

    event = decoys.capture_event(
        request, HoneyEvent.DecoyType.CANARY, enforce_rate_limit=False
    )
    # enforce_rate_limit=False never rate-limits, so an event is always returned.
    assert event is not None
    logger.info(
        "canary: token %s (%r) tripped by %s — event=%s",
        token.token_id,
        token.label,
        ip,
        event.id,
    )

    enrich_event.delay(event.id)
    _fire_canary_alerts(event, ip)
    return event


def _fire_canary_alerts(event: HoneyEvent, ip: str) -> None:
    """Evaluate alert rules against the canary trip right away.

    A canary is a high-signal trip-wire — the point is an immediate alert — so we
    don't wait for the enrichment pipeline's own rule pass. We materialise the
    attacker profile (enrichment will reuse this same row) and run
    :func:`~apps.alerts.evaluator.evaluate_rules`, which fires any rule whose
    condition matches — e.g. ``decoy_type == "canary"``. Its per-(rule, attacker)
    mute window means the later enrichment pass won't re-send the same alert.
    """
    profile, _ = AttackerProfile.objects.get_or_create(ip=ip)
    evaluate_rules(profile, event)

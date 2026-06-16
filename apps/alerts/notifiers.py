"""Alert delivery channels.

Each notifier turns a fired :class:`~apps.alerts.models.AlertRule` plus the
attacker/event that tripped it into a message and ships it somewhere (Slack, an
inbox, a generic webhook). They share one hard rule: **never raise**. Alert
delivery hangs off the tail of ``enrich_event`` (architecture.md), and a flaky
webhook or SMTP server must not break enrichment — so every ``send`` catches its
own failures, logs them, and returns ``False`` instead of propagating.

``send`` returns ``True`` only when delivery is confirmed. The evaluator uses
that to decide whether to start the per-attacker mute window: a failed send is
left un-throttled so the next matching event can retry.
"""

import logging
from typing import Any, Protocol

import requests
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse

from apps.alerts.models import AlertRule
from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile

logger = logging.getLogger(__name__)


def _admin_profile_url(attacker: AttackerProfile) -> str:
    """Build a link to the attacker's admin change page.

    Returns an absolute URL when ``ADMIN_BASE_URL`` is configured, otherwise the
    relative admin path. Empty string for an unsaved profile (e.g. the admin
    "send test alert" action), so callers can omit the link line.
    """
    if attacker.pk is None:
        return ""
    path = reverse("admin:profiles_attackerprofile_change", args=[attacker.pk])
    base = settings.ADMIN_BASE_URL.rstrip("/")
    return f"{base}{path}" if base else path


def _summary_lines(
    rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
) -> list[str]:
    """The shared human-readable body shared by every channel, as lines."""
    timestamp = event.timestamp.isoformat() if event.timestamp else "—"
    lines = [
        f"Rule: {rule.name}",
        f"IP: {attacker.ip}",
        f"Country: {attacker.country or attacker.country_code or '—'}",
        f"Threat score: {attacker.threat_score}",
        f"Tags: {', '.join(attacker.tags) if attacker.tags else '—'}",
        f"Decoy: {event.decoy_type}",
        f"Path: {event.method} {event.path}",
        f"Time: {timestamp}",
    ]
    url = _admin_profile_url(attacker)
    if url:
        lines.append(f"Profile: {url}")
    return lines


def _build_payload(
    rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
) -> dict[str, Any]:
    """Structured JSON body for the generic webhook channel."""
    return {
        "rule": rule.name,
        "ip": attacker.ip,
        "country": attacker.country,
        "country_code": attacker.country_code,
        "threat_score": attacker.threat_score,
        "is_known_scanner": attacker.is_known_scanner,
        "tags": attacker.tags,
        "decoy_type": event.decoy_type,
        "path": event.path,
        "method": event.method,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "profile_url": _admin_profile_url(attacker),
    }


class Notifier(Protocol):
    """Structural type every channel satisfies."""

    def send(
        self, rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
    ) -> bool: ...


class SlackNotifier:
    """POST a formatted message to an incoming-webhook URL."""

    def send(
        self, rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
    ) -> bool:
        webhook_url = rule.notifier_config.get("webhook_url")
        if not webhook_url:
            logger.error("SlackNotifier: rule %r has no webhook_url configured", rule.name)
            return False

        text = "🚨 *HoneyDjango alert*\n" + "\n".join(_summary_lines(rule, attacker, event))
        try:
            response = requests.post(
                webhook_url,
                json={"text": text},
                timeout=settings.ALERT_WEBHOOK_TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("SlackNotifier failed for rule %r: %s", rule.name, exc)
            return False
        return True


class EmailNotifier:
    """Send the alert by email via Django's configured email backend."""

    def send(
        self, rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
    ) -> bool:
        recipient = rule.notifier_config.get("to")
        if not recipient:
            logger.error("EmailNotifier: rule %r has no 'to' configured", rule.name)
            return False
        recipients = recipient if isinstance(recipient, list) else [recipient]

        subject = f"[HoneyDjango] {rule.name}: {attacker.ip} (threat {attacker.threat_score})"
        body = "\n".join(_summary_lines(rule, attacker, event))
        try:
            send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                recipients,
                fail_silently=False,
            )
        except Exception as exc:  # SMTP/connection errors must never break enrichment.
            logger.warning("EmailNotifier failed for rule %r: %s", rule.name, exc)
            return False
        return True


class WebhookNotifier:
    """POST a structured JSON payload to an arbitrary URL."""

    def send(
        self, rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent
    ) -> bool:
        url = rule.notifier_config.get("url")
        if not url:
            logger.error("WebhookNotifier: rule %r has no url configured", rule.name)
            return False

        try:
            response = requests.post(
                url,
                json=_build_payload(rule, attacker, event),
                timeout=settings.ALERT_WEBHOOK_TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("WebhookNotifier failed for rule %r: %s", rule.name, exc)
            return False
        return True


NOTIFIER_REGISTRY: dict[str, type[Notifier]] = {
    AlertRule.NotifierType.SLACK: SlackNotifier,
    AlertRule.NotifierType.EMAIL: EmailNotifier,
    AlertRule.NotifierType.WEBHOOK: WebhookNotifier,
}

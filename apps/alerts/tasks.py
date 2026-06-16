"""Asynchronous alert dispatch.

The evaluator (apps/alerts/evaluator.py) decides *which* rules fire; the actual
notifier call — a Slack/webhook POST or an SMTP send — runs here, in a Celery
task, so a slow or hung notifier can never stall the enrichment pipeline that
triggered it. ``evaluate_rules`` mutes the (rule, attacker) pair and stamps
``last_fired`` synchronously, then hands the delivery off via
``dispatch_alert.delay(rule_id, attacker_id, event_id)``.

We pass ids rather than objects because Celery serialises arguments to JSON over
the broker — the task reloads the rows itself. If any of the three has been
deleted since dispatch, that's terminal (it won't reappear), so we log and
return without retrying. The notifiers already swallow their own delivery errors
and return ``False``; we don't double-handle those. Only an *unexpected*
exception — a bug, or a transient fault from a notifier that broke its
never-raise contract — triggers a bounded retry.
"""

import logging

from celery import Task, shared_task

from apps.alerts.models import AlertRule
from apps.alerts.notifiers import NOTIFIER_REGISTRY
from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile

logger = logging.getLogger(__name__)


@shared_task(  # type: ignore[misc]
    bind=True, max_retries=2, default_retry_delay=5, queue="alerts"
)
def dispatch_alert(self: Task, rule_id: int, attacker_id: int, event_id: int) -> None:
    """Deliver a fired alert via its configured notifier.

    Idempotent in the way that matters: re-running with the same ids just
    re-attempts delivery. A missing rule/attacker/event is logged and skipped
    (no retry — it won't come back).
    """
    try:
        rule = AlertRule.objects.get(pk=rule_id)
        attacker = AttackerProfile.objects.get(pk=attacker_id)
        event = HoneyEvent.objects.get(pk=event_id)
    except (
        AlertRule.DoesNotExist,
        AttackerProfile.DoesNotExist,
        HoneyEvent.DoesNotExist,
    ) as exc:
        logger.warning(
            "dispatch_alert: object gone (rule=%s attacker=%s event=%s): %s",
            rule_id,
            attacker_id,
            event_id,
            exc,
        )
        return

    notifier_cls = NOTIFIER_REGISTRY.get(rule.notifier_type)
    if notifier_cls is None:
        logger.error(
            "dispatch_alert: rule %r has unknown notifier_type %r",
            rule.name,
            rule.notifier_type,
        )
        return

    try:
        delivered = notifier_cls().send(rule, attacker, event)
    except Exception as exc:
        # Notifiers are contracted never to raise (they log + return False). If
        # one does, treat it as a bug or transient fault and retry a bounded
        # number of times rather than dropping the alert.
        logger.exception(
            "dispatch_alert: notifier for rule %r raised unexpectedly", rule.name
        )
        raise self.retry(exc=exc)

    if not delivered:
        # The notifier already logged why it failed and returned False. Don't
        # retry — a 4xx webhook or a missing config won't fix itself on a re-run.
        logger.warning(
            "dispatch_alert: rule %r failed to deliver for %s", rule.name, attacker.ip
        )
        return

    logger.info(
        "dispatch_alert: rule %r delivered for %s via %s",
        rule.name,
        attacker.ip,
        rule.notifier_type,
    )

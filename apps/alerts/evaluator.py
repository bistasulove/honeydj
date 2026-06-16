"""Alert rule evaluation.

After ``enrich_event`` folds an event into its attacker profile, it calls
:func:`evaluate_rules`. We walk every enabled :class:`AlertRule`, test its
JSON ``condition`` against the freshly-updated profile (and the triggering
event), and dispatch a notification when it matches — unless we already alerted
on this rule for this attacker within the mute window.

A ``condition`` is a flat ``{"field": ..., "op": ..., "value": ...}`` triple,
e.g. ``{"field": "threat_score", "op": "gte", "value": 80}``. Only the fields
in :data:`FIELD_RESOLVERS` and the operators in :data:`OPS` are supported; an
unknown field or operator is logged and treated as "no match" rather than
raising, so a malformed rule can't break enrichment.

Per-attacker throttling note: ``AlertRule.last_fired`` is a single column — it
records the last time the rule fired *at all* (handy for the admin list), but it
can't track per-attacker state. The "once per attacker per hour" mute therefore
lives in the cache, keyed by ``(rule, attacker)``.
"""

import logging
import operator
from typing import Any, Callable

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.alerts.models import AlertRule
from apps.alerts.notifiers import NOTIFIER_REGISTRY
from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile

logger = logging.getLogger(__name__)


# Maps a condition ``field`` to how we read its current value off the profile or
# event. Anything not listed here is unsupported.
FIELD_RESOLVERS: dict[str, Callable[[AttackerProfile, HoneyEvent], Any]] = {
    "threat_score": lambda attacker, event: attacker.threat_score,
    "is_known_scanner": lambda attacker, event: attacker.is_known_scanner,
    "event_count": lambda attacker, event: attacker.event_count,
    "country_code": lambda attacker, event: attacker.country_code,
    "decoy_type": lambda attacker, event: event.decoy_type,
}


def _ordered(cmp: Callable[[Any, Any], bool]) -> Callable[[Any, Any], bool]:
    """Wrap an ordering comparator so a ``None`` actual (e.g. no country yet) or
    a type mismatch is a clean "no match" instead of a ``TypeError``."""

    def compare(actual: Any, expected: Any) -> bool:
        if actual is None:
            return False
        try:
            return cmp(actual, expected)
        except TypeError:
            return False

    return compare


def _op_in(actual: Any, expected: Any) -> bool:
    """``actual in expected`` — only meaningful when ``expected`` is a collection."""
    if not isinstance(expected, (list, tuple, set)):
        return False
    return actual in expected


OPS: dict[str, Callable[[Any, Any], bool]] = {
    "gt": _ordered(operator.gt),
    "gte": _ordered(operator.ge),
    "lt": _ordered(operator.lt),
    "lte": _ordered(operator.le),
    "eq": operator.eq,
    "in": _op_in,
}


def evaluate_rules(attacker: AttackerProfile, event: HoneyEvent) -> None:
    """Fire any enabled alert rule whose condition matches ``attacker``/``event``.

    Never raises: a broken rule or a failing notifier is logged and skipped so
    enrichment always completes.
    """
    for rule in AlertRule.objects.filter(enabled=True):
        if not condition_matches(rule.condition, attacker, event):
            continue
        if _recently_fired(rule, attacker):
            logger.debug(
                "alert: rule %r already fired for %s within mute window, skipping",
                rule.name,
                attacker.ip,
            )
            continue
        _fire(rule, attacker, event)


def condition_matches(
    condition: dict[str, Any], attacker: AttackerProfile, event: HoneyEvent
) -> bool:
    """Return whether ``condition`` holds for the given attacker/event.

    A malformed condition (missing keys, unknown field/operator) returns
    ``False`` and is logged — it never raises.
    """
    try:
        field = condition["field"]
        op = condition["op"]
        expected = condition["value"]
    except (KeyError, TypeError):
        logger.warning("alert: malformed condition %r", condition)
        return False

    resolver = FIELD_RESOLVERS.get(field)
    comparator = OPS.get(op)
    if resolver is None or comparator is None:
        logger.warning("alert: unsupported field %r or operator %r", field, op)
        return False

    return comparator(resolver(attacker, event), expected)


def _throttle_key(rule: AlertRule, attacker: AttackerProfile) -> str:
    return f"alert:fired:{rule.pk}:{attacker.pk}"


def _recently_fired(rule: AlertRule, attacker: AttackerProfile) -> bool:
    return cache.get(_throttle_key(rule, attacker)) is not None


def _fire(rule: AlertRule, attacker: AttackerProfile, event: HoneyEvent) -> None:
    """Dispatch ``rule`` via its notifier; throttle only on confirmed delivery."""
    notifier_cls = NOTIFIER_REGISTRY.get(rule.notifier_type)
    if notifier_cls is None:
        logger.error(
            "alert: rule %r has unknown notifier_type %r", rule.name, rule.notifier_type
        )
        return

    delivered = notifier_cls().send(rule, attacker, event)
    if not delivered:
        # Leave the rule un-muted so the next matching event from this attacker
        # gets another shot at delivery.
        logger.warning(
            "alert: rule %r failed to deliver for %s; will retry next event",
            rule.name,
            attacker.ip,
        )
        return

    cache.set(
        _throttle_key(rule, attacker), True, settings.ALERT_REFIRE_WINDOW_SECONDS
    )
    # last_fired is the rule-wide "last fired at all" stamp for the admin list.
    # Use .update() to touch only that column and avoid clobbering concurrent edits.
    AlertRule.objects.filter(pk=rule.pk).update(last_fired=timezone.now())
    logger.info("alert: rule %r fired for %s via %s", rule.name, attacker.ip, rule.notifier_type)

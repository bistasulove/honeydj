"""Django admin (django-unfold) for alert rules.

Unlike the immutable capture models, AlertRule is fully operator-editable: staff
create rules, toggle them on/off inline, and fire a one-off test notification to
confirm a webhook or inbox is wired up correctly.
"""

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone
from unfold.admin import ModelAdmin

from apps.alerts.models import AlertRule
from apps.alerts.notifiers import NOTIFIER_REGISTRY
from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile


def _sample_attacker_and_event() -> tuple[AttackerProfile, HoneyEvent]:
    """Build an unsaved, representative attacker/event pair for a test alert."""
    attacker = AttackerProfile(
        ip="203.0.113.42",
        country_code="RU",
        country="Russia",
        org="Example Hosting",
        threat_score=92,
        event_count=7,
        tags=["sql_injection", "sqlmap"],
        is_known_scanner=True,
    )
    event = HoneyEvent(
        ip="203.0.113.42",
        path="/admin/",
        method="POST",
        decoy_type=HoneyEvent.DecoyType.ADMIN,
        user_agent="sqlmap/1.7.2#stable (https://sqlmap.org)",
        timestamp=timezone.now(),
    )
    return attacker, event


@admin.register(AlertRule)
class AlertRuleAdmin(ModelAdmin):  # type: ignore[misc]  # unfold ships no stubs
    list_display = (
        "name",
        "condition_display",
        "notifier_type",
        "enabled",
        "last_fired",
    )
    list_editable = ("enabled",)
    list_filter = ("notifier_type", "enabled")
    search_fields = ("name",)
    readonly_fields = ("last_fired",)
    actions = ("send_test_alert",)

    @admin.display(description="Condition")
    def condition_display(self, obj: AlertRule) -> str:
        condition = obj.condition or {}
        field = condition.get("field", "?")
        op = condition.get("op", "?")
        value = condition.get("value", "?")
        return f"{field} {op} {value}"

    @admin.action(description="Send test alert")
    def send_test_alert(
        self, request: HttpRequest, queryset: QuerySet[AlertRule]
    ) -> None:
        attacker, event = _sample_attacker_and_event()
        for rule in queryset:
            notifier_cls = NOTIFIER_REGISTRY.get(rule.notifier_type)
            if notifier_cls is None:
                self.message_user(
                    request,
                    f"{rule.name}: unknown notifier type {rule.notifier_type!r}.",
                    level="error",
                )
                continue
            delivered = notifier_cls().send(rule, attacker, event)
            if delivered:
                self.message_user(request, f"{rule.name}: test alert sent.", level="success")
            else:
                self.message_user(
                    request,
                    f"{rule.name}: test alert failed — check notifier_config and logs.",
                    level="error",
                )

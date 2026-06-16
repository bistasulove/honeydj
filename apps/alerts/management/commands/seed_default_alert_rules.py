"""Seed a couple of sensible starter alert rules.

Idempotent: rules are keyed by name via ``get_or_create``, so re-running won't
create duplicates. Both rules are seeded **disabled** — operators fill in the
real webhook URL / inbox in the admin and flip them on, so we never start firing
to an unconfigured channel.
"""

from typing import Any

from django.core.management.base import BaseCommand

from apps.alerts.models import AlertRule

DEFAULT_RULES = [
    {
        "name": "Known scanner detected",
        "condition": {"field": "is_known_scanner", "op": "eq", "value": True},
        "notifier_type": AlertRule.NotifierType.SLACK,
        "notifier_config": {"webhook_url": ""},
    },
    {
        "name": "High threat score (>= 80)",
        "condition": {"field": "threat_score", "op": "gte", "value": 80},
        "notifier_type": AlertRule.NotifierType.EMAIL,
        "notifier_config": {"to": ""},
    },
]


class Command(BaseCommand):
    help = "Create the default (disabled) alert rules if they don't already exist."

    def handle(self, *args: Any, **options: Any) -> None:
        for spec in DEFAULT_RULES:
            rule, created = AlertRule.objects.get_or_create(
                name=spec["name"],
                defaults={
                    "condition": spec["condition"],
                    "notifier_type": spec["notifier_type"],
                    "notifier_config": spec["notifier_config"],
                    "enabled": False,
                },
            )
            verb = "Created" if created else "Already exists"
            self.stdout.write(f"{verb}: {rule.name}")

from django.db import models


class AlertRule(models.Model):
    class NotifierType(models.TextChoices):
        SLACK = "slack", "Slack"
        EMAIL = "email", "Email"
        WEBHOOK = "webhook", "Webhook"

    name = models.CharField(max_length=200)
    condition = models.JSONField()  # {"field": "threat_score", "op": "gt", "value": 80}
    notifier_type = models.CharField(max_length=20, choices=NotifierType.choices)
    notifier_config = models.JSONField()  # {"url": "..."} or {"to": "..."}
    enabled = models.BooleanField(default=True)
    last_fired = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

from django.db import models

from apps.profiles.models import AttackerProfile


class HoneyEvent(models.Model):
    class DecoyType(models.TextChoices):
        ADMIN = "admin", "Admin"
        ENV = "env", "Env"
        WP_ADMIN = "wpAdmin", "WP Admin"
        API = "api", "API"
        CUSTOM = "custom", "Custom"

    ip = models.GenericIPAddressField(db_index=True)
    path = models.CharField(max_length=2048)
    method = models.CharField(max_length=8)
    headers = models.JSONField()
    body = models.JSONField(null=True, blank=True)
    ja3_hash = models.CharField(max_length=64, null=True, blank=True)
    user_agent = models.TextField()
    decoy_type = models.CharField(max_length=50, choices=DecoyType.choices)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    attacker = models.ForeignKey(
        AttackerProfile,
        null=True,
        on_delete=models.SET_NULL,
        related_name="events",
    )
    enriched = models.BooleanField(default=False)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["ip", "timestamp"]),
        ]

    def __str__(self) -> str:
        return f"{self.method} {self.path} from {self.ip}"

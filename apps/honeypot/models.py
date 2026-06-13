import uuid

from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class CanaryToken(models.Model):
    class TokenType(models.TextChoices):
        URL = "url", "URL"
        EMAIL = "email", "Email"
        DNS = "dns", "DNS"
        AWS_KEY = "aws_key", "AWS Key"
        FILE = "file", "File"

    token_id = models.UUIDField(default=uuid.uuid4, unique=True)
    token_type = models.CharField(max_length=20, choices=TokenType.choices)
    label = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="canary_tokens")
    triggered = models.BooleanField(default=False)
    triggered_at = models.DateTimeField(null=True, blank=True)
    trigger_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ["-pk"]

    def __str__(self) -> str:
        return f"{self.label} ({self.token_type})"

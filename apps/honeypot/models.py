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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-pk"]

    def __str__(self) -> str:
        return f"{self.label} ({self.token_type})"


class DecoyRoute(models.Model):
    class DecoyType(models.TextChoices):
        ADMIN = "admin", "Admin"
        ENV = "env", "Env"
        WP_ADMIN = "wpAdmin", "WP Admin"
        API = "api", "API"
        CUSTOM = "custom", "Custom"

    path_pattern = models.CharField(max_length=500)
    is_regex = models.BooleanField(default=False)
    decoy_type = models.CharField(max_length=50, choices=DecoyType.choices)
    response_template = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True, db_index=True)
    description = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    priority = models.SmallIntegerField(default=0)

    class Meta:
        ordering = ["-priority", "path_pattern"]

    def __str__(self) -> str:
        return f"{self.path_pattern} ({self.decoy_type})"

from django.contrib.postgres.fields import ArrayField
from django.db import models


class AttackerProfile(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    asn = models.CharField(max_length=20, null=True, blank=True)
    org = models.CharField(max_length=200, null=True, blank=True)
    country_code = models.CharField(max_length=2, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    lon = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    event_count = models.PositiveIntegerField(default=0)
    threat_score = models.SmallIntegerField(default=0)  # 0-100
    tags = ArrayField(models.CharField(max_length=50), default=list)
    is_known_scanner = models.BooleanField(default=False)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self) -> str:
        return self.ip

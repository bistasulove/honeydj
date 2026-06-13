from django.db import models


class ThreatFeedEntry(models.Model):
    class Source(models.TextChoices):
        ABUSEIPDB = "abuseipdb", "AbuseIPDB"
        VIRUSTOTAL = "virustotal", "VirusTotal"

    ip = models.GenericIPAddressField(db_index=True)
    source = models.CharField(max_length=50, choices=Source.choices)
    confidence = models.SmallIntegerField()
    category = models.CharField(max_length=100, null=True, blank=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ["-expires_at"]

    def __str__(self) -> str:
        return f"{self.ip} ({self.source})"

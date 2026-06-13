import uuid
from datetime import timedelta

import factory
from django.contrib.auth import get_user_model
from django.utils import timezone
from factory.django import DjangoModelFactory

from apps.alerts.models import AlertRule
from apps.events.models import HoneyEvent
from apps.feeds.models import ThreatFeedEntry
from apps.honeypot.models import CanaryToken, DecoyRoute
from apps.profiles.models import AttackerProfile

User = get_user_model()


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda o: f"{o.username}@example.com")
    password = factory.PostGenerationMethodCall("set_password", "testpass123")


class AttackerProfileFactory(DjangoModelFactory):
    class Meta:
        model = AttackerProfile

    ip = factory.Sequence(lambda n: f"10.{(n // 65536) % 256}.{(n // 256) % 256}.{n % 256}")
    asn = factory.Sequence(lambda n: f"AS{n + 1000}")
    org = factory.Faker("company")
    country_code = "US"
    country = "United States"
    city = factory.Faker("city")
    lat = factory.Faker("latitude")
    lon = factory.Faker("longitude")
    event_count = 0
    threat_score = 0
    tags = factory.List([])
    is_known_scanner = False


class HoneyEventFactory(DjangoModelFactory):
    class Meta:
        model = HoneyEvent

    ip = factory.Faker("ipv4")
    path = "/admin/"
    method = "GET"
    headers = factory.Dict({"User-Agent": "Mozilla/5.0", "Host": "example.com"})
    body = None
    ja3_hash = None
    user_agent = factory.Faker("user_agent")
    decoy_type = HoneyEvent.DecoyType.ADMIN
    attacker = factory.SubFactory(AttackerProfileFactory)
    enriched = False


class CanaryTokenFactory(DjangoModelFactory):
    class Meta:
        model = CanaryToken

    token_id = factory.LazyFunction(uuid.uuid4)
    token_type = CanaryToken.TokenType.URL
    label = factory.Faker("sentence", nb_words=4)
    created_by = factory.SubFactory(UserFactory)
    triggered = False
    triggered_at = None
    trigger_ip = None


class DecoyRouteFactory(DjangoModelFactory):
    class Meta:
        model = DecoyRoute

    path_pattern = factory.Sequence(lambda n: f"/decoy/{n}/")
    is_regex = False
    decoy_type = DecoyRoute.DecoyType.ADMIN
    response_template = "default"
    is_active = True
    description = factory.Faker("sentence", nb_words=5)
    priority = 0


class AlertRuleFactory(DjangoModelFactory):
    class Meta:
        model = AlertRule

    name = factory.Faker("sentence", nb_words=3)
    condition = factory.Dict({"field": "threat_score", "op": "gt", "value": 80})
    notifier_type = AlertRule.NotifierType.SLACK
    notifier_config = factory.Dict({"url": "https://hooks.slack.com/test"})
    enabled = True
    last_fired = None


class ThreatFeedEntryFactory(DjangoModelFactory):
    class Meta:
        model = ThreatFeedEntry

    ip = factory.Faker("ipv4")
    source = ThreatFeedEntry.Source.ABUSEIPDB
    confidence = 80
    category = "scanner"
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=7))

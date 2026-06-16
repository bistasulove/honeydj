"""Alert evaluation engine: rule matching, throttling, and the three notifiers."""

import pytest
import responses
from django.core import mail

from apps.alerts.evaluator import condition_matches, evaluate_rules
from apps.alerts.models import AlertRule
from apps.alerts.notifiers import (
    NOTIFIER_REGISTRY,
    EmailNotifier,
    SlackNotifier,
    WebhookNotifier,
)
from tests.factories import AlertRuleFactory, AttackerProfileFactory, HoneyEventFactory

pytestmark = pytest.mark.django_db

SLACK_URL = "https://hooks.slack.com/services/T000/B000/test"
HOOK_URL = "https://example.com/webhook"

HIGH_SCORE = {"field": "threat_score", "op": "gte", "value": 80}


def _slack_rule(**overrides):
    defaults = {
        "condition": HIGH_SCORE,
        "notifier_type": AlertRule.NotifierType.SLACK,
        "notifier_config": {"webhook_url": SLACK_URL},
        "enabled": True,
    }
    defaults.update(overrides)
    return AlertRuleFactory(**defaults)


# --------------------------------------------------------------------------- #
# condition_matches                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "op,value,score,expected",
    [
        ("gt", 80, 90, True),
        ("gt", 80, 80, False),
        ("gte", 80, 80, True),
        ("lt", 50, 40, True),
        ("lte", 40, 40, True),
        ("eq", 75, 75, True),
        ("eq", 75, 76, False),
    ],
)
def test_condition_matches_numeric_ops(op, value, score, expected):
    attacker = AttackerProfileFactory(threat_score=score)
    event = HoneyEventFactory(attacker=attacker)
    condition = {"field": "threat_score", "op": op, "value": value}
    assert condition_matches(condition, attacker, event) is expected


def test_condition_matches_in_op_on_country():
    attacker = AttackerProfileFactory(country_code="RU")
    event = HoneyEventFactory(attacker=attacker)
    condition = {"field": "country_code", "op": "in", "value": ["RU", "CN"]}
    assert condition_matches(condition, attacker, event) is True


def test_condition_matches_reads_decoy_type_from_event():
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker, decoy_type="env")
    condition = {"field": "decoy_type", "op": "eq", "value": "env"}
    assert condition_matches(condition, attacker, event) is True


def test_condition_matches_known_scanner_bool():
    attacker = AttackerProfileFactory(is_known_scanner=True)
    event = HoneyEventFactory(attacker=attacker)
    condition = {"field": "is_known_scanner", "op": "eq", "value": True}
    assert condition_matches(condition, attacker, event) is True


def test_condition_unsupported_field_is_no_match():
    attacker = AttackerProfileFactory(threat_score=99)
    event = HoneyEventFactory(attacker=attacker)
    assert condition_matches({"field": "nope", "op": "gt", "value": 1}, attacker, event) is False


def test_condition_malformed_is_no_match():
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    assert condition_matches({"field": "threat_score"}, attacker, event) is False


def test_condition_none_value_does_not_raise():
    # country_code is None; an ordering op against it must be a clean no-match.
    attacker = AttackerProfileFactory(country_code=None)
    event = HoneyEventFactory(attacker=attacker)
    assert condition_matches({"field": "country_code", "op": "gt", "value": "A"}, attacker, event) is False


# --------------------------------------------------------------------------- #
# evaluate_rules                                                               #
# --------------------------------------------------------------------------- #


@responses.activate
def test_evaluate_fires_on_match():
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory(threat_score=90)
    event = HoneyEventFactory(attacker=attacker)
    rule = _slack_rule()

    evaluate_rules(attacker, event)

    assert len(responses.calls) == 1
    rule.refresh_from_db()
    assert rule.last_fired is not None


@responses.activate
def test_evaluate_does_not_fire_when_condition_false():
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory(threat_score=10)
    event = HoneyEventFactory(attacker=attacker)
    _slack_rule()

    evaluate_rules(attacker, event)

    assert len(responses.calls) == 0


@responses.activate
def test_evaluate_does_not_fire_twice_within_window():
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory(threat_score=90)
    event = HoneyEventFactory(attacker=attacker)
    _slack_rule()

    evaluate_rules(attacker, event)
    evaluate_rules(attacker, event)

    assert len(responses.calls) == 1


@responses.activate
def test_evaluate_fires_again_for_a_different_attacker():
    responses.add(responses.POST, SLACK_URL, status=200)
    _slack_rule()

    for ip in ("203.0.113.1", "203.0.113.2"):
        attacker = AttackerProfileFactory(ip=ip, threat_score=90)
        event = HoneyEventFactory(attacker=attacker)
        evaluate_rules(attacker, event)

    assert len(responses.calls) == 2


@responses.activate
def test_evaluate_skips_disabled_rules():
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory(threat_score=90)
    event = HoneyEventFactory(attacker=attacker)
    _slack_rule(enabled=False)

    evaluate_rules(attacker, event)

    assert len(responses.calls) == 0


@responses.activate
def test_evaluate_failed_delivery_leaves_rule_unmuted():
    # First send fails (500) → not throttled; second send succeeds and fires.
    responses.add(responses.POST, SLACK_URL, status=500)
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory(threat_score=90)
    event = HoneyEventFactory(attacker=attacker)
    rule = _slack_rule()

    evaluate_rules(attacker, event)
    rule.refresh_from_db()
    assert rule.last_fired is None  # failure didn't stamp last_fired

    evaluate_rules(attacker, event)
    rule.refresh_from_db()
    assert rule.last_fired is not None
    assert len(responses.calls) == 2


# --------------------------------------------------------------------------- #
# notifiers                                                                    #
# --------------------------------------------------------------------------- #


def test_registry_maps_every_notifier_type():
    assert set(NOTIFIER_REGISTRY) == set(AlertRule.NotifierType.values)


@responses.activate
def test_slack_notifier_success():
    responses.add(responses.POST, SLACK_URL, status=200)
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = _slack_rule()

    assert SlackNotifier().send(rule, attacker, event) is True
    assert "text" in responses.calls[0].request.body.decode() or responses.calls[0].request.body


@responses.activate
def test_slack_notifier_http_error_returns_false():
    responses.add(responses.POST, SLACK_URL, status=500)
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = _slack_rule()

    assert SlackNotifier().send(rule, attacker, event) is False


def test_slack_notifier_missing_config_returns_false():
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = _slack_rule(notifier_config={})

    assert SlackNotifier().send(rule, attacker, event) is False


def test_email_notifier_success():
    attacker = AttackerProfileFactory(threat_score=88)
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.EMAIL,
        notifier_config={"to": "ops@example.com"},
    )

    assert EmailNotifier().send(rule, attacker, event) is True
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["ops@example.com"]
    assert str(attacker.ip) in mail.outbox[0].body


def test_email_notifier_missing_config_returns_false():
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.EMAIL, notifier_config={}
    )

    assert EmailNotifier().send(rule, attacker, event) is False
    assert mail.outbox == []


def test_email_notifier_backend_error_returns_false(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("smtp down")

    monkeypatch.setattr("apps.alerts.notifiers.send_mail", boom)
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.EMAIL,
        notifier_config={"to": "ops@example.com"},
    )

    assert EmailNotifier().send(rule, attacker, event) is False


@responses.activate
def test_webhook_notifier_success():
    responses.add(responses.POST, HOOK_URL, status=200)
    attacker = AttackerProfileFactory(ip="203.0.113.5", threat_score=70)
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.WEBHOOK,
        notifier_config={"url": HOOK_URL},
    )

    assert WebhookNotifier().send(rule, attacker, event) is True
    body = responses.calls[0].request.body.decode()
    assert "203.0.113.5" in body


@responses.activate
def test_webhook_notifier_http_error_returns_false():
    responses.add(responses.POST, HOOK_URL, status=503)
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.WEBHOOK,
        notifier_config={"url": HOOK_URL},
    )

    assert WebhookNotifier().send(rule, attacker, event) is False


def test_webhook_notifier_missing_config_returns_false():
    attacker = AttackerProfileFactory()
    event = HoneyEventFactory(attacker=attacker)
    rule = AlertRuleFactory(
        notifier_type=AlertRule.NotifierType.WEBHOOK, notifier_config={}
    )

    assert WebhookNotifier().send(rule, attacker, event) is False


# --------------------------------------------------------------------------- #
# seed_default_alert_rules management command                                 #
# --------------------------------------------------------------------------- #


def test_seed_command_is_idempotent():
    from django.core.management import call_command

    call_command("seed_default_alert_rules")
    call_command("seed_default_alert_rules")

    assert AlertRule.objects.count() == 2
    assert not AlertRule.objects.filter(enabled=True).exists()


# --------------------------------------------------------------------------- #
# AlertRuleAdmin                                                               #
# --------------------------------------------------------------------------- #


def _admin():
    from django.contrib import admin as django_admin

    from apps.alerts.admin import AlertRuleAdmin

    return AlertRuleAdmin(AlertRule, django_admin.site)


def test_admin_condition_display():
    rule = _slack_rule(condition={"field": "threat_score", "op": "gte", "value": 80})
    assert _admin().condition_display(rule) == "threat_score gte 80"


@responses.activate
def test_admin_send_test_alert_action(rf):
    responses.add(responses.POST, SLACK_URL, status=200)
    rule = _slack_rule()
    model_admin = _admin()
    messages = []
    model_admin.message_user = lambda request, message, level=None: messages.append((message, level))

    model_admin.send_test_alert(rf.get("/"), AlertRule.objects.filter(pk=rule.pk))

    assert len(responses.calls) == 1
    assert any("test alert sent" in msg for msg, _ in messages)

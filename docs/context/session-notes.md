# Session notes — 2026-06-15 (alert evaluation engine)

## What was built
- `apps/alerts/evaluator.py` (new) — `evaluate_rules(attacker, event)` +
  `condition_matches()`. `FIELD_RESOLVERS` (threat_score, is_known_scanner,
  event_count, country_code, decoy_type) and `OPS` (gt/gte/lt/lte/eq/in).
- `apps/alerts/notifiers.py` (new) — `SlackNotifier`/`EmailNotifier`/
  `WebhookNotifier` + `NOTIFIER_REGISTRY`. All catch own errors, log, return
  False (never raise). Messages carry ip/country/score/tags/decoy/ts + admin link.
- `apps/alerts/admin.py` — `AlertRuleAdmin` (unfold): condition_display,
  list_editable enabled, "Send test alert" action.
- `apps/alerts/management/commands/seed_default_alert_rules.py` (new) — idempotent,
  seeds 2 **disabled** rules (known-scanner→slack, score≥80→email).
- `apps/events/tasks.py` — `enrich_event` calls `evaluate_rules` after commit.
- `honeydj/settings/base.py` — ALERT_REFIRE_WINDOW_SECONDS (3600),
  ALERT_WEBHOOK_TIMEOUT, ADMIN_BASE_URL, DEFAULT_FROM_EMAIL.
- `tests/test_alerts.py` (new) — 32 tests.

## Key decisions
- Per-attacker throttle lives in the **cache** (key `alert:fired:{rule}:{attacker}`)
  because `AlertRule.last_fired` is one column and can't track per-attacker state.
  `last_fired` still stamped per fire for the admin list.
- Failed delivery leaves the rule **un-muted** → next event retries; only a
  confirmed send starts the mute window.
- Tests in top-level `tests/`, NOT `apps/alerts/` (repo convention; autouse
  cache/DB fixtures live in tests/conftest.py).
- No migration: AlertRule already existed; only settings added.

## Broken / incomplete
- Nothing broken. Suite: 124 passed, coverage 88.63%, ruff + mypy clean.

## Next task to resume from
Not yet committed — `git add -A` then commit (feat: alert evaluation engine).
Then: alert dispatch via Celery (move `_fire` into a `dispatch_alert` task so a
slow webhook doesn't block enrichment) — `apps/alerts/tasks.py` is still a stub.

## Gotchas
- Run tests inside Docker: `docker compose exec -T web python -m pytest`. Local
  `which python` points at a different project's venv (django-llm-audit) with no
  deps; honeydj's `.venv` is empty too.
- Slack config key is `webhook_url`; generic webhook uses `url`; email uses `to`.
  AlertRuleFactory default is `{"url": ...}` — override per-test for slack/email.

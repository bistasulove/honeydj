# Session notes — 2026-06-17 (canary token system)

## What was built
- `apps/honeypot/canary.py` — `generate_url_token(label, created_by)`,
  `get_canary_url(token, request)` (absolute, via `reverse` +
  `build_absolute_uri`), `record_trigger(token, request)` (race-safe conditional
  UPDATE claim, logs `canary` HoneyEvent, `enrich_event.delay()`, fires alerts).
- `apps/honeypot/views.py` — `CanaryPingView` (public, csrf-exempt, GET/POST),
  returns a 42-byte transparent 1×1 GIF with no-store headers; unknown UUID → 404.
- `apps/honeypot/admin_views.py` — `CanaryTokenCreateView` (LoginRequired): GET
  serves a self-posting form, POST mints a url token → JSON {token_id, ping_url}.
- `apps/honeypot/urls.py` — `canary/<uuid:token_id>/ping/` (root-mounted, outside
  admin prefix) + `canary/create/`.
- `apps/dashboard/admin.py` — `CanaryTokenAdmin` (Copy URL action + unfold
  `actions_list` "Create Token" button → create view).
- `apps/honeypot/decoys.py` — `capture_event` gained `enforce_rate_limit` kwarg.
- Models: `events` `CANARY` decoy type; `honeypot` `CanaryToken.created_at`.
  Migrations `events/0003`, `honeypot/0003`, applied.
- `tests/test_canary.py` — 11 tests.

## Key decisions
- Canary alerts fire **synchronously** in the trip path (not just async
  enrichment) so operators hear immediately; evaluator's per-(rule,attacker) mute
  prevents the later enrichment pass double-sending.
- Trips skip rate limiting (`enforce_rate_limit=False`) — rare, high-value, and
  guarded once by `triggered`.
- Added `created_at` because the requested admin `list_display` referenced it.

## Broken / incomplete
- Nothing broken. Suite: 142 passed, 89.98% coverage, ruff + mypy clean.
- No `AlertRule` yet exists with `condition decoy_type == "canary"` — needed to
  actually deliver a canary notification.

## Next task to resume from
Decide on / create a default canary AlertRule (decoy_type eq canary), then
commit (`feat: canary token system`).

## Gotchas
- Long-lived `web`/`celery` containers cache old code — **restart after model/
  enum changes** (a stale process 500'd on the new `CANARY` member until restart).
- `client_ip()` trusts first `X-Forwarded-For` hop.

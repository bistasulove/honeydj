# Session notes — 2026-06-13

## What was built
- `apps/honeypot/middleware.py` — `HoneyMiddleware`: in-process route cache
  (`_route_cache`/`_regex_cache`/`_cache_loaded_at`, 60s TTL), two-pass match
  (exact then regex), event capture, Redis rate limiting, decoy responses,
  Celery dispatch.
- `apps/honeypot/apps.py` — `ready()` wires `post_save`/`post_delete` on
  `DecoyRoute` to `invalidate_route_cache`.
- `honeydj/settings/base.py` — added `HoneyMiddleware` after `SecurityMiddleware`.
- `apps/events/geoip.py` — maxminddb wrapper for the Celery task (NOT called
  from middleware). Cached reader, empty-dict fallback if DB file absent.
- `tests/conftest.py`, `tests/test_middleware.py`, `tests/test_geoip.py` —
  15 tests, all passing. conftest resets the module-level route cache and
  swaps in a locmem cache so tests need no Redis.

## Key decisions
- GeoIP runs in the Celery `enrich_event` task, NOT middleware (per
  architecture.md; keeps hot path I/O-free). User confirmed this choice.
- Route cache is in-process Python globals (speed), not Redis. Rate-limit
  counter IS Redis (`honeydj:ratelimit:{ip}`, db 0, SET NX + INCR, 5min/50).

## Broken / incomplete
- `apps/events/tasks.py` `enrich_event` is still a logging placeholder — no
  GeoIP/AttackerProfile/AbuseIPDB/TTP/WebSocket yet.
- mypy reports 2 pre-existing errors in tasks.py (untyped `@shared_task`).
- Decoy fake views (FakeAdminView etc.) not built; middleware renders inline.

## Next task to resume from
Implement `enrich_event(event_id)` in `apps/events/tasks.py` per
architecture.md steps 1-8, using `apps/events/geoip.py` for step 2.

## Gotchas
- `MIDDLEWARE`/settings changes need `docker compose restart web` (read once
  at boot). Route DB changes do NOT (signal/TTL handle it).
- post_save signal only invalidates the cache in the process that saved.
  `manage.py shell` is a separate process → web sees new route only after 60s TTL.
- No `curl` in web image; use python urllib or browser (port 8000 mapped).
- RedisCache prefixes keys: `:1:honeydj:ratelimit:<ip>`.
- Demo left DecoyRoute pk=1 (`/.env`) + 2 HoneyEvents in local DB.

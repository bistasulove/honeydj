# Session notes — 2026-06-14

## What was built
- `apps/events/tasks.py` — `enrich_event` fully implemented (was a
  placeholder). GeoIP + AbuseIPDB + TTP, atomic profile update, post-commit
  WebSocket broadcast. Rich start/signals/done logging.
- `apps/feeds/adapters/__init__.py` + `abuseipdb.py` (new) — typed `/check`
  adapter; returns None on missing key or any HTTP/parse error.
- `apps/events/ttp.py` (new) — regex classifier, 10 technique classes.
- `honeydj/settings/base.py` — ABUSEIPDB_*, THREAT_FEED_TTL_DAYS,
  KNOWN_SCANNER_JA3. `requirements/base.txt` — added `responses`.
- Capture fixes: `apps/honeypot/decoys.py` (store `get_full_path()`),
  `apps/honeypot/views.py` (decoy views now `csrf_exempt`).
- mypy: `apps/{events,alerts}/tasks.py` (annotate `self: Task`, ignore[misc]),
  `apps/{events,feeds,dashboard}/urls.py` + `dashboard/routing.py` (typed
  lists), `setup.cfg` (relaxed strict for `tests.*` only).
- Tests (new): `test_tasks.py`, `test_ttp.py`, `test_abuseipdb.py`; added
  csrf/full-path/encoded cases to `test_views.py`.

## Key decisions
- Idempotency: skip if `enriched=True`; all scoring in one
  `select_for_update` txn (event then profile) so concurrent tasks for the
  same IP can't double-count. +10/new tag, +20 first AbuseIPDB>50, +30 first
  scanner JA3, cap 100. AbuseIPDB-once enforced via ThreatFeedEntry `created`.
- TTP scans raw + URL-decoded text to catch %20/+/%2f evasions.
- HTTP I/O outside the txn; broadcast via `transaction.on_commit`.

## Broken / incomplete
- `EventConsumer` / `dashboard/routing.py` still empty — broadcast (type
  `event.enriched`) has no subscriber yet.
- `alerts/tasks.py` `dispatch_alert` still a placeholder.
- No `GeoLite2-City.mmdb` and no ABUSEIPDB_API_KEY locally → those steps skip.

## Next task to resume from
Build `apps/events/consumers.py` `EventConsumer` (handle `event.enriched`),
wire `dashboard/routing.py`, and the HTMX `hx-ext="ws"` table row.

## Gotchas
- Celery does NOT hot-reload; web container holds capture code. After code
  changes: `docker compose restart celery web`.
- Tests/lint/mypy run in docker. `responses` was pip-installed into the live
  container (root) — rebuild to persist from requirements.
- `mypy .` clean; app code strict, `tests.*` relaxed. 60 tests, 92.7%.

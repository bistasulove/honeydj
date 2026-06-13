# Architecture decisions

## Middleware pipeline
HoneyMiddleware sits at the top of MIDDLEWARE in settings.
Order: SecurityMiddleware → HoneyMiddleware → everything else.
Must complete in <5ms — zero blocking I/O in the hot path.

## Route matching — DB-backed with in-process cache
DecoyRoute rows are loaded from DB at Django startup and cached in
a module-level variable in apps/honeypot/middleware.py:

  _route_cache: list[DecoyRoute] = []
  _cache_loaded_at: datetime | None = None
  CACHE_TTL = 60  # seconds

On each request: if cache is stale, reload from DB (one query,
ordered by priority desc). Match against request.path using
exact string match first, then regex for is_regex=True routes.
First match wins. Non-matching requests pass through untouched.

Cache invalidation: DecoyRoute post_save and post_delete signals
set _cache_loaded_at = None, forcing reload on next request.

## Event capture — what happens synchronously
On a decoy hit, before returning the response:
1. Read full headers into dict (exclude Cookie, Authorization)
2. Read request body, truncate at 64KB
3. Extract JA3 hash from X-JA3-Hash header (set by nginx)
4. HoneyEvent.objects.create(...) — synchronous DB write
5. enrich_event.delay(event_id) — Celery dispatch, non-blocking
6. Return decoy response

AttackerProfile lookup/create happens inside the Celery task,
NOT in the middleware. Middleware only creates HoneyEvent.

## Celery enrichment task — what happens asynchronously
Task: enrich_event(event_id: int) in apps/events/tasks.py
Steps in order:
1. Load HoneyEvent, skip if already enriched=True (idempotency)
2. GeoIP lookup via maxminddb — local file, fast
3. get_or_create AttackerProfile for the IP
4. AbuseIPDB check (if API key configured, else skip)
5. TTP classification — scan body + path for known patterns
6. Update AttackerProfile: threat_score, tags, last_seen, event_count
7. Set event.enriched = True, save
8. channel_layer.group_send("events", {...}) — WebSocket push

## Decoy response policy
Always return a convincing fake response. Never 404.
FakeAdminView: renders a real-looking Django admin login page
FakeDotEnvView: returns plausible .env content as text/plain
FakeWpAdminView: returns a WordPress login form (terminal page, not a
  redirect — a redirect to /wp-login.php self-loops when the same decoy is
  served at /wp-login.php or matched by a broad DecoyRoute regex)
FakeApiDebugView: returns plausible JSON with fake stack trace
Response should include realistic headers (Server, X-Powered-By).

## Rate limiting on event writes
Redis counter key: honeydj:ratelimit:{ip}
Window: 5 minutes, max 50 events stored per IP per window.
Above limit: log a warning, skip HoneyEvent.objects.create,
return the same decoy response (attacker must not know they're throttled).
Counter incremented regardless — tracks total probe volume.

## WebSocket live updates
After enrichment, Celery sends to Django Channels group "events".
EventConsumer (apps/events/consumers.py) broadcasts to all
connected dashboard sessions. HTMX hx-ext="ws" on the event
table prepends a new row without page reload.
Only send serialised fields needed for the table row — not the
full event — to keep WebSocket payloads small.

## AttackerProfile threat score
Starts at 0. Incremented by:
+10 per unique TTP tag detected
+20 if IP appears in AbuseIPDB with confidence > 50
+30 if JA3 hash matches known scanner list
+15 if Tor exit node or known VPN (future: ip-api.com)
Capped at 100. Never decremented — score is cumulative.

## Security of the honeypot itself
Admin URL: /hd-{ADMIN_URL_SUFFIX}/ — suffix from env var, never hardcoded.
Admin binds to 127.0.0.1 in production — nginx reverse proxy only.
Stored payloads: truncated at 64KB, HTML-escaped on render.
Headers stored: strip Cookie and Authorization before saving to DB.
settings.json denies Claude from reading .env — no accidental secret exposure.
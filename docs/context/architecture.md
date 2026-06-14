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

## JA3 fingerprinting & scanner detection
Two client-fingerprint signals live in apps/honeypot/fingerprint.py and feed
both the capture path (apps/honeypot/decoys.py) and enrichment (apps/events/tasks.py).

**JA3 (TLS).** nginx computes the JA3 over the TLS ClientHello and forwards the
MD5 in the `X-JA3-Hash` request header — use nginx's `$ssl_ja3_hash` (the MD5),
not `$ssl_ja3` (the raw string), so values match the published dict. The app
never sees the handshake. `parse_ja3_header(request)` returns the header value
or None; nginx only emits the header over TLS, so plain HTTP yields None.

A JA3 identifies the client's *TLS library*, not the tool: it survives a forged
User-Agent, but is shared by every tool on the same library and shifts between
library versions. So a match is strong evidence, not proof, and the dict is a
deliberately conservative high-signal allowlist.

`KNOWN_SCANNER_JA3: dict[hash, tool_name]` — published MD5s sourced from the
trisulnsm JA3 fingerprint DB and Salesforce's JA3 writeup:
- curl — 764b8952…, c458ae71…, 9f198208… (libcurl/OpenSSL builds)
- python-requests — c398c555… (urllib3/OpenSSL; sqlmap's JA3 collides here)
- nikto — a563bb12…, f4262963…, 5eeeafdb… (2.1.6, Kali)
- metasploit — 16f17c89…, 950ccdd6…, 6825b330…, ee031b87… (aux/HTTP scanners)
- meterpreter — 5d65ea3f… (Linux payload)
- zgrab — dc76bc3a… (ZMap UMich scanner)

Not in the dict: masscan and nmap don't complete an application TLS handshake by
default (no stable JA3); sqlmap rides Python's `ssl` so its JA3 collides with
python-requests; scrapy's JA3 (Twisted/pyOpenSSL) isn't authoritatively
published. All are caught by User-Agent instead. `settings.KNOWN_SCANNER_JA3`
is an env-configured list that extends the dict with unnamed local hashes.

**User-Agent.** `classify_user_agent(ua) -> list[str]` matches default UAs for
sqlmap, nikto, masscan, nmap, zgrab, nuclei, metasploit/meterpreter,
python-requests, go-http-client, and curl/ (anchored to the `curl/` version
delimiter). Trivially spoofed, so it's a hint — but most scanners never change
their default UA. Tags are stable identifiers; renaming one orphans accrued score.

**Where each runs.**
- Capture (decoys.capture_event): `ja3_hash` from parse_ja3_header; UA tags
  stored on `HoneyEvent.tags` for immediate pre-enrichment visibility.
- Enrich (tasks.enrich_event): re-derives both. If the JA3 is in the dict or the
  settings list, set `AttackerProfile.is_known_scanner = True` and add **+30**
  once per IP (first match only). The matched tool name (from the dict) plus the
  UA tags are added to `profile.tags`, deduped. These tool-identity tags carry
  **no score of their own** — the +30 already credits the JA3 signal, and unlike
  TTP tags (+10 each) they name the tool rather than a technique.

## Security of the honeypot itself
Admin URL: /hd-{ADMIN_URL_SUFFIX}/ — suffix from env var, never hardcoded.
Admin binds to 127.0.0.1 in production — nginx reverse proxy only.
Stored payloads: truncated at 64KB, HTML-escaped on render.
Headers stored: strip Cookie and Authorization before saving to DB.
settings.json denies Claude from reading .env — no accidental secret exposure.
# Architecture decisions

## Middleware-first capture
HoneyMiddleware intercepts before any view. Sub-5ms target — no blocking I/O.
GeoIP is local mmdb (in-process). All enrichment via Celery.

## JSONB strategy
Raw request bodies, headers, enrichment results all stored as JSONB.
Enables @> containment queries: find all events matching a payload pattern.
Do NOT use JSONField for things with known schema — use proper columns.

## WebSocket flow
Event captured → Celery enriches → channel_layer.group_send("events") →
EventConsumer broadcasts → HTMX hx-ext="ws" updates table row.

## Decoy response policy
Always return a plausible response (fake login page, fake JSON).
Never return 404 — alerts sophisticated attackers they hit a trap.

## Rate-limit on writes
Max 50 events/IP/5min stored. Redis counter. Excess logged as aggregate.
Prevents DB flood via DDoS against honeypot routes.

## Security of the honeypot itself
Admin served at /hd-{SECRET_SUFFIX}/ — set in env var ADMIN_URL_PREFIX.
Admin binds to 127.0.0.1 only in production — reverse proxy handles SSL.
Stored payloads are truncated at 64KB and HTML-escaped on render.
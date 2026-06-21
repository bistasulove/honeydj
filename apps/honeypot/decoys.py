"""Shared decoy rendering and event capture.

Both ``HoneyMiddleware`` (DB-routed decoys) and the explicit decoy views in
``views.py`` render the same fake responses and capture events the same way.
That logic lives here so it stays in one place: the fake content must look
identical regardless of which entry point an attacker hits, and an event
captured by a view must be indistinguishable from one captured by middleware.

Nothing here does blocking network I/O — enrichment (GeoIP, AbuseIPDB, TTP,
WebSocket push) is deferred to the ``enrich_event`` Celery task by the caller.
"""

import logging

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse

from apps.events.models import HoneyEvent
from apps.honeypot.fingerprint import classify_user_agent, parse_ja3_header
from apps.honeypot.models import DecoyRoute

logger = logging.getLogger(__name__)

# --- Event capture limits -------------------------------------------------
MAX_BODY_BYTES = 64 * 1024
MAX_PATH_CHARS = 2048
_EXCLUDED_HEADERS = {"cookie", "authorization"}

# --- Rate limiting --------------------------------------------------------
RATE_LIMIT_KEY = "honeydj:ratelimit:{ip}"
RATE_LIMIT_WINDOW = 5 * 60  # seconds
RATE_LIMIT_MAX = 50  # events stored per IP per window

# --- Decoy responses ------------------------------------------------------
_SERVER_HEADER = "nginx/1.24.0"
_POWERED_BY_HEADER = "PHP/8.1.2"

_FAKE_ADMIN_HTML = (
    "<!DOCTYPE html><html><head><title>Log in | Django site admin</title></head>"
    '<body class="login"><div id="container"><div id="header">'
    "<h1>Django administration</h1></div>"
    '<form action="/admin/login/" method="post">'
    '<div class="form-row"><label>Username:</label>'
    '<input type="text" name="username" autofocus></div>'
    '<div class="form-row"><label>Password:</label>'
    '<input type="password" name="password"></div>'
    '<div class="submit-row"><input type="submit" value="Log in"></div>'
    "</form></div></body></html>"
)

_FAKE_ENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "APP_KEY=base64:Zk8w2nQx9vR3sT6yB1cF4hJ7mP0qL5dW8eA2gK9nM4U=\n"
    "DB_CONNECTION=mysql\n"
    "DB_HOST=127.0.0.1\n"
    "DB_PORT=3306\n"
    "DB_DATABASE=app_prod\n"
    "DB_USERNAME=app_user\n"
    "DB_PASSWORD=N0tR3alPa55w0rd!\n"
    "REDIS_HOST=127.0.0.1\n"
    "MAIL_HOST=smtp.mailgun.org\n"
)

# Terminal WordPress login form — NOT a redirect. A redirect to /wp-login.php
# loops when this same decoy is served at /wp-login.php (or matched by a broad
# DecoyRoute regex). The login form is the natural terminal page and just as
# convincing — it's what an attacker probing /wp-admin/ expects to land on.
_FAKE_WP_HTML = (
    '<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">'
    "<title>Log In &lsaquo; WordPress</title>"
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<meta name="robots" content="noindex,noarchive"></head>'
    '<body class="login wp-core-ui"><div id="login">'
    '<h1><a href="https://wordpress.org/">WordPress</a></h1>'
    '<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
    '<p><label for="user_login">Username or Email Address</label>'
    '<input type="text" name="log" id="user_login" autocomplete="username" size="20"></p>'
    '<div class="user-pass-wrap"><label for="user_pass">Password</label>'
    '<input type="password" name="pwd" id="user_pass" autocomplete="current-password" size="20"></div>'
    '<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever">'
    ' <label for="rememberme">Remember Me</label></p>'
    '<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In">'
    '<input type="hidden" name="redirect_to" value="/wp-admin/"></p>'
    "</form></div></body></html>"
)

_FAKE_API_JSON = (
    '{"error": "Internal Server Error", "status": 500, '
    '"trace": "Traceback (most recent call last):\\n  File \\"app/views.py\\", '
    'line 142, in dispatch\\n    return handler(request)\\n  File '
    '\\"app/services/db.py\\", line 31, in query\\n    cursor.execute(sql)\\n'
    'OperationalError: connection to server failed"}'
)


def render_decoy(decoy_type: str) -> HttpResponse:
    """Return a convincing fake response for ``decoy_type``. Never a 404."""
    if decoy_type == DecoyRoute.DecoyType.ENV:
        response = HttpResponse(_FAKE_ENV, content_type="text/plain; charset=utf-8")
    elif decoy_type == DecoyRoute.DecoyType.API:
        response = HttpResponse(_FAKE_API_JSON, content_type="application/json", status=500)
    elif decoy_type == DecoyRoute.DecoyType.WP_ADMIN:
        response = HttpResponse(_FAKE_WP_HTML, content_type="text/html; charset=utf-8")
    else:  # ADMIN and CUSTOM
        response = HttpResponse(_FAKE_ADMIN_HTML, content_type="text/html; charset=utf-8")
    response["Server"] = _SERVER_HEADER
    response["X-Powered-By"] = _POWERED_BY_HEADER
    return response


def client_ip(request: HttpRequest) -> str:
    """First hop of X-Forwarded-For (set by nginx), falling back to REMOTE_ADDR."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return str(request.META.get("REMOTE_ADDR", "0.0.0.0"))


def capture_headers(request: HttpRequest) -> dict[str, str]:
    return {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _EXCLUDED_HEADERS
    }


def capture_body(request: HttpRequest) -> str | None:
    raw = request.body[:MAX_BODY_BYTES]
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")


def over_rate_limit(ip: str) -> bool:
    """Increment the per-IP probe counter and report whether it exceeds the cap.

    The counter is always incremented (tracks total probe volume); only event
    storage is throttled.
    """
    key = RATE_LIMIT_KEY.format(ip=ip)
    cache.add(key, 0, timeout=RATE_LIMIT_WINDOW)
    try:
        count = cache.incr(key)
    except ValueError:
        # Key expired between add and incr — re-seed and treat as first hit.
        cache.set(key, 1, timeout=RATE_LIMIT_WINDOW)
        count = 1
    return count > RATE_LIMIT_MAX


def capture_event(
    request: HttpRequest, decoy_type: str, *, enforce_rate_limit: bool = True
) -> HoneyEvent | None:
    """Store a HoneyEvent for a decoy hit, or return ``None`` if rate-limited.

    The probe counter is incremented regardless of the cap. The caller is
    responsible for dispatching ``enrich_event`` and logging rate-limit skips,
    so each entry point logs against its own logger.

    ``enforce_rate_limit=False`` skips the per-IP cap (and its probe counter)
    entirely, so the event is always stored. Canary trips use this: a token
    fires at most once (guarded by ``CanaryToken.triggered``), it's a rare,
    high-value signal, and it shouldn't be charged against — or dropped by — the
    decoy probe budget.
    """
    ip = client_ip(request)
    if enforce_rate_limit and over_rate_limit(ip):
        return None
    user_agent = request.headers.get("User-Agent", "")
    return HoneyEvent.objects.create(
        ip=ip,
        # Full path, not request.path — the query string carries SQLi/traversal
        # payloads the TTP classifier needs to see.
        path=request.get_full_path()[:MAX_PATH_CHARS],
        method=request.method or "",
        headers=capture_headers(request),
        body=capture_body(request),
        ja3_hash=parse_ja3_header(request),
        tags=classify_user_agent(user_agent),
        user_agent=user_agent,
        decoy_type=decoy_type,
    )

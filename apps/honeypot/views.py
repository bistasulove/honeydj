"""Explicit decoy views.

Each view answers a well-known attack path with a convincing fake response and
logs the attempt as a HoneyEvent tagged with its decoy type. They share their
rendering and capture logic with HoneyMiddleware via apps/honeypot/decoys.py.

These are reached only for paths that have no matching DecoyRoute — middleware
runs before URL resolution and short-circuits anything it matches, so a request
is never captured twice. ``dispatch`` is overridden (rather than ``get``) so
every method an attacker might probe with (GET, POST, HEAD, …) is captured and
answered the same way.
"""

import base64
import logging
import uuid

from django.http import Http404, HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.events.tasks import enrich_event
from apps.honeypot import canary, decoys
from apps.honeypot.models import CanaryToken, DecoyRoute

logger = logging.getLogger(__name__)

# A 43-byte, fully transparent 1×1 GIF. Returned by the canary ping endpoint so a
# token embedded as <img src="…/ping/"> renders invisibly inside a document or
# HTML email — the fetch trips the wire, the pixel leaves no visible trace.
_PIXEL_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)


@method_decorator(csrf_exempt, name="dispatch")
class _DecoyView(View):
    """Base view: capture the hit, dispatch enrichment, return the decoy response.

    Subclasses set ``decoy_type`` to one of DecoyRoute.DecoyType.

    CSRF-exempt: attackers POST credentials and payloads without a token, and
    capturing those is the whole point — a 403 would discard them before
    ``dispatch`` runs. (Decoys read the request and return canned content; they
    never mutate honeypot state, so exempting them is safe.)
    """

    decoy_type: str

    def dispatch(self, request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        event = decoys.capture_event(request, self.decoy_type)
        if event is None:
            logger.warning(
                "Rate limit exceeded for %s on %s — skipping event capture",
                decoys.client_ip(request),
                request.path,
            )
        else:
            enrich_event.delay(event.id)
        return decoys.render_decoy(self.decoy_type)


class FakeAdminView(_DecoyView):
    """A real-looking Django admin login page."""

    decoy_type = DecoyRoute.DecoyType.ADMIN


class FakeDotEnvView(_DecoyView):
    """Plausible .env contents served as text/plain."""

    decoy_type = DecoyRoute.DecoyType.ENV


class FakeWpAdminView(_DecoyView):
    """WordPress login form (terminal — never redirects, so it can't loop)."""

    decoy_type = DecoyRoute.DecoyType.WP_ADMIN


class FakeApiDebugView(_DecoyView):
    """Plausible JSON 500 with a fake stack trace."""

    decoy_type = DecoyRoute.DecoyType.API


@method_decorator(csrf_exempt, name="dispatch")
class CanaryPingView(View):
    """Public trip-wire endpoint for a URL canary token.

    Mounted at the site root, *outside* the admin prefix and with no auth: the
    whole point is that an attacker who finds the token can reach it. The first
    request stamps the token and logs a ``canary`` HoneyEvent (see
    ``canary.record_trigger``); subsequent requests are silently idempotent. An
    unknown token UUID is a 404, indistinguishable from any other dead URL.

    Always answers with an invisible 1×1 GIF — never an HTML page or JSON — so the
    token can be embedded as an image in a document or email and trip silently
    when rendered. CSRF-exempt because trips arrive as bare GETs/POSTs with no
    token, exactly like the decoy views.
    """

    def get(self, request: HttpRequest, token_id: uuid.UUID) -> HttpResponse:
        return self._ping(request, token_id)

    def post(self, request: HttpRequest, token_id: uuid.UUID) -> HttpResponse:
        return self._ping(request, token_id)

    def _ping(self, request: HttpRequest, token_id: uuid.UUID) -> HttpResponse:
        try:
            token = CanaryToken.objects.get(token_id=token_id)
        except CanaryToken.DoesNotExist:
            raise Http404("Unknown canary token")
        canary.record_trigger(token, request)
        # No-cache so a proxy can't satisfy a later trip from cache and hide it.
        response = HttpResponse(_PIXEL_GIF, content_type="image/gif")
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

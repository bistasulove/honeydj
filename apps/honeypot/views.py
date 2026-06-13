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

import logging

from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.events.tasks import enrich_event
from apps.honeypot import decoys
from apps.honeypot.models import DecoyRoute

logger = logging.getLogger(__name__)


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

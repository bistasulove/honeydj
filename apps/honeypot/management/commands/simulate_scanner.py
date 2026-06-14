"""Simulate a scanner hitting a decoy route, end to end.

A dev/demo helper that exercises the real capture path: it builds a request with
a forged ``X-JA3-Hash`` and scanner ``User-Agent`` and runs it through the actual
``HoneyMiddleware`` (the same RequestFactory pattern the test suite uses), so the
JA3 + UA fingerprinting, rate limiting and ``HoneyEvent`` write all happen for
real. In local dev there is no nginx to set ``X-JA3-Hash`` and no TLS, so we
supply the header by hand exactly as nginx's ``$ssl_ja3_hash`` would.

By default it then runs enrichment inline so you immediately see the resulting
``AttackerProfile`` (scanner flag, threat score, tags). Pass ``--async`` to
instead dispatch ``enrich_event`` to Celery, mirroring production, and watch the
worker log / dashboard pick it up.

Not for production: it fabricates traffic and reaches into ``enrich_event.delay``.
"""

from argparse import ArgumentParser
from typing import Any
from unittest.mock import patch

from django.core.management.base import BaseCommand, CommandError
from django.http import HttpResponse
from django.test import RequestFactory

from apps.events.models import HoneyEvent
from apps.events.tasks import enrich_event
from apps.honeypot.fingerprint import KNOWN_SCANNER_JA3
from apps.honeypot.middleware import HoneyMiddleware
from apps.honeypot.models import DecoyRoute
from apps.profiles.models import AttackerProfile

# A known-scanner JA3 (meterpreter, per fingerprint.KNOWN_SCANNER_JA3) and a
# default scanner User-Agent (sqlmap), so the out-of-the-box run trips both signals.
DEFAULT_JA3 = "5d65ea3fb1d4aa7d826733d2f2cbbb1d"
DEFAULT_UA = "sqlmap/1.7.2#stable (https://sqlmap.org)"
DEFAULT_IP = "203.0.113.77"
DEFAULT_PATH = "/admin/"


class Command(BaseCommand):
    help = "Simulate a scanner hit on a decoy route to exercise the capture + enrich pipeline."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--ip", default=DEFAULT_IP, help=f"Source IP (default {DEFAULT_IP}).")
        parser.add_argument(
            "--path", default=DEFAULT_PATH, help=f"Decoy path to hit (default {DEFAULT_PATH})."
        )
        parser.add_argument(
            "--ja3",
            default=DEFAULT_JA3,
            help="JA3 hash for the X-JA3-Hash header; pass '' to send none.",
        )
        parser.add_argument(
            "--ua", dest="user_agent", default=DEFAULT_UA, help="User-Agent header to send."
        )
        parser.add_argument(
            "--body",
            default=None,
            help="Optional request body (sent as a POST) — handy to also trip the TTP classifier.",
        )
        parser.add_argument(
            "--async",
            dest="use_celery",
            action="store_true",
            help="Dispatch enrich_event to Celery instead of running it inline.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        ip: str = options["ip"]
        path: str = options["path"]
        ja3: str = options["ja3"]
        user_agent: str = options["user_agent"]
        body: str | None = options["body"]
        use_celery: bool = options["use_celery"]

        route = self._ensure_route(path)
        self.stdout.write(f"Decoy route: {route.path_pattern} ({route.get_decoy_type_display()})")
        if ja3:
            tool = KNOWN_SCANNER_JA3.get(ja3)
            verdict = f"known scanner → {tool}" if tool else "not in KNOWN_SCANNER_JA3"
            self.stdout.write(f"JA3 {ja3} — {verdict}")

        event_id = self._fire(ip, path, ja3, user_agent, body)
        if event_id is None:
            raise CommandError(
                f"No event captured for {ip} {path} — rate limited, or the path "
                "didn't match the decoy route. Try a fresh --ip."
            )

        event = HoneyEvent.objects.get(pk=event_id)
        self.stdout.write(self.style.SUCCESS(f"Captured HoneyEvent #{event.id}"))
        self.stdout.write(f"  ja3_hash : {event.ja3_hash}")
        self.stdout.write(f"  ua tags  : {event.tags}")  # set at capture by classify_user_agent

        if use_celery:
            enrich_event.delay(event_id)
            self.stdout.write(
                self.style.WARNING(
                    "Dispatched enrich_event to Celery. Watch the worker log / dashboard, "
                    f"then inspect AttackerProfile for {ip}."
                )
            )
            return

        enrich_event(event_id)
        self._report_profile(ip)

    def _ensure_route(self, path: str) -> DecoyRoute:
        """Return a decoy route matching ``path``, creating a basic one if absent.

        Respects an existing (e.g. seeded) route rather than overwriting its
        decoy type or template.
        """
        route, _ = DecoyRoute.objects.get_or_create(
            path_pattern=path,
            defaults={
                "decoy_type": DecoyRoute.DecoyType.ADMIN,
                "response_template": "default",
                "description": "simulate_scanner generated route",
                "is_active": True,
                "priority": 10,
            },
        )
        return route

    def _fire(
        self, ip: str, path: str, ja3: str, user_agent: str, body: str | None
    ) -> int | None:
        """Run a forged request through HoneyMiddleware; return the captured event id.

        ``enrich_event.delay`` is intercepted so capture and enrichment stay
        decoupled here — ``handle`` decides whether to enrich inline or dispatch.
        We patch ``.delay`` on the task object itself, which is the same Celery
        singleton the middleware imported, so its dispatch is captured too.
        Returns ``None`` when the middleware stored no event (rate limited or the
        path matched no decoy route).
        """
        factory = RequestFactory()
        if body is not None:
            request = factory.post(path, data=body, content_type="text/plain")
        else:
            request = factory.get(path)
        # Set the transport/header META directly — capture reads request.headers
        # (lazily built from these HTTP_* keys) and client_ip falls back to REMOTE_ADDR.
        request.META["REMOTE_ADDR"] = ip
        request.META["HTTP_USER_AGENT"] = user_agent
        if ja3:
            request.META["HTTP_X_JA3_HASH"] = ja3

        captured: list[int] = []
        with patch.object(enrich_event, "delay", side_effect=captured.append):
            response: HttpResponse = HoneyMiddleware(_not_a_decoy)(request)

        self.stdout.write(f"Decoy responded {response.status_code} ({len(response.content)} bytes)")
        return captured[0] if captured else None

    def _report_profile(self, ip: str) -> None:
        profile = AttackerProfile.objects.filter(ip=ip).first()
        if profile is None:
            self.stdout.write(self.style.ERROR(f"No AttackerProfile for {ip} after enrichment."))
            return
        self.stdout.write(self.style.SUCCESS(f"AttackerProfile {ip}"))
        self.stdout.write(f"  is_known_scanner : {profile.is_known_scanner}")
        self.stdout.write(f"  threat_score     : {profile.threat_score}")
        self.stdout.write(f"  tags             : {profile.tags}")
        self.stdout.write(f"  event_count      : {profile.event_count}")


def _not_a_decoy(request: Any) -> HttpResponse:
    """Downstream handler if the path somehow matches no decoy route."""
    return HttpResponse("no decoy matched", status=404)

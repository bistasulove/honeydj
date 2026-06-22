"""Simulate scanner traffic against the decoys, end to end.

A dev/demo helper that exercises the *real* capture path: it builds requests with
forged ``X-JA3-Hash`` and scanner ``User-Agent`` headers and runs them through the
actual ``HoneyMiddleware`` (the same RequestFactory pattern the test suite uses),
so JA3 + UA fingerprinting, rate limiting and the ``HoneyEvent`` write all happen
for real. In local dev there is no nginx to set ``X-JA3-Hash`` and no TLS, so we
supply the header by hand exactly as nginx's ``$ssl_ja3_hash`` would.

Two modes:

* **Scenario (default)** — fires a curated wave of events that lights up the whole
  pipeline: hits against four decoy types from several public IPs with realistic
  scanner UAs/JA3s, a SQL-injection payload, a canary-token trip, and an attacker
  whose score climbs high enough to trip an ``AlertRule``. Enrichment is dispatched
  to Celery (the demo stack runs a worker), so the live dashboard updates as the
  worker processes each event. Use ``--watch`` to pace one event at a time for a
  screen recording, and ``--count`` to size the wave. This is the mode the
  ``docs/DEMO.md`` runbook drives.

* **Single shot** — pass ``--ip`` to fire exactly one request with full control of
  path/JA3/UA/body, enriched inline so you immediately see the resulting
  ``AttackerProfile``. Pass ``--async`` to dispatch to Celery instead.

Not for production: it fabricates traffic and reaches into ``.delay``.
"""

import random
import time
from argparse import ArgumentParser
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Max
from django.http import HttpResponse
from django.test import RequestFactory
from django.utils import timezone

from apps.alerts.models import AlertRule
from apps.events.models import HoneyEvent
from apps.events.tasks import enrich_event
from apps.honeypot import canary
from apps.honeypot.fingerprint import KNOWN_SCANNER_JA3
from apps.honeypot.middleware import HoneyMiddleware
from apps.honeypot.models import CanaryToken, DecoyRoute
from apps.profiles.models import AttackerProfile

User = get_user_model()

# --- Single-shot defaults -------------------------------------------------
# A known-scanner JA3 (meterpreter, per fingerprint.KNOWN_SCANNER_JA3) and a
# default scanner User-Agent (sqlmap), so a bare single-shot trips both signals.
DEFAULT_JA3 = "5d65ea3fb1d4aa7d826733d2f2cbbb1d"
DEFAULT_UA = "sqlmap/1.7.2#stable (https://sqlmap.org)"
DEFAULT_PATH = "/admin/"

# --- Realistic scanner identities -----------------------------------------
# Default User-Agents the tools ship with (classify_user_agent tags on these).
UA_SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"
UA_NIKTO = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"
UA_PYREQUESTS = "python-requests/2.31.0"
UA_MASSCAN = "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"
UA_NUCLEI = "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
UA_GO = "Go-http-client/1.1"
UA_CURL = "curl/8.4.0"

# Published JA3 MD5s from fingerprint.KNOWN_SCANNER_JA3 (empty string = none, e.g.
# masscan/nmap/nuclei which don't complete a stable application TLS handshake).
JA3_METERPRETER = "5d65ea3fb1d4aa7d826733d2f2cbbb1d"
JA3_NIKTO = "a563bb123396e545f5704a9a2d16bcb0"
JA3_PYREQUESTS = "c398c55518355639c5a866c15784f969"
JA3_CURL = "764b8952983230b0ac23dbd3741d2bb0"

# Public, routable IPs chosen *only* because MaxMind GeoLite2 resolves them to a
# spread of countries, so the live map drops markers in different places. They are
# well-known DNS resolvers / a Tor exit — NOT real attackers, just GeoIP fodder.
# (TEST-NET ranges like 203.0.113.0/24 are reserved-for-docs and won't geolocate.)
IP_DE = "185.220.101.34"     # Germany — Tor exit (our high-score "known scanner")
IP_RU = "77.88.8.8"          # Russia — Yandex DNS
IP_CN = "114.114.114.114"    # China — 114DNS
IP_NL = "80.80.80.80"        # Netherlands — Freenom DNS (canary tripper)
IP_US = "8.8.8.8"            # United States — Google DNS

# Decoy routes the scenario hits. HoneyMiddleware matches on request.path (query
# stripped), so these patterns must equal the path without its query string.
SCENARIO_ROUTES: list[tuple[str, str]] = [
    ("/admin/", DecoyRoute.DecoyType.ADMIN),
    ("/.env", DecoyRoute.DecoyType.ENV),
    ("/wp-admin/", DecoyRoute.DecoyType.WP_ADMIN),
    ("/api/debug/", DecoyRoute.DecoyType.API),
]

# Demo alert rules so dispatch_alert actually fires. Created idempotently and
# clearly labelled "Demo:". The webhook URL is a placeholder — delivery will fail
# (logged by the notifier) but the *dispatch* still fires, which is the point;
# point it at a real Slack/webhook URL to see a delivered notification.
DEMO_WEBHOOK_URL = "https://example.com/honeydj-demo-webhook"
DEMO_ALERT_RULES: list[dict[str, Any]] = [
    {
        "name": "Demo: known scanner detected",
        "condition": {"field": "is_known_scanner", "op": "eq", "value": True},
        "notifier_type": AlertRule.NotifierType.WEBHOOK,
        "notifier_config": {"url": DEMO_WEBHOOK_URL},
    },
    {
        "name": "Demo: canary token tripped",
        "condition": {"field": "decoy_type", "op": "eq", "value": "canary"},
        "notifier_type": AlertRule.NotifierType.WEBHOOK,
        "notifier_config": {"url": DEMO_WEBHOOK_URL},
    },
]


@dataclass(frozen=True)
class Step:
    """One simulated request in the scenario wave.

    ``kind`` is ``"decoy"`` (run through HoneyMiddleware) or ``"canary"`` (trip a
    fresh canary token). ``country`` is a display label only — the real geo comes
    from GeoIP enrichment. ``path`` may carry a query string holding a payload; for
    canary steps it is ignored.
    """

    kind: str
    ip: str
    country: str
    user_agent: str
    ja3: str
    method: str
    path: str
    body: str | None
    note: str


# Essentials first so even a small --count still covers every required signal:
# four decoy types, known-scanner JA3 + UA, a SQLi payload, a canary trip, and an
# attacker (IP_DE) whose repeated hits push its score past the alert threshold.
_ESSENTIAL_STEPS: list[Step] = [
    Step("decoy", IP_DE, "Germany", UA_SQLMAP, JA3_METERPRETER, "GET",
         "/admin/?id=1%20OR%201%3D1%20--%20", None,
         "known-scanner JA3 + sqlmap UA, SQLi in query → ADMIN decoy"),
    Step("decoy", IP_DE, "Germany", UA_SQLMAP, JA3_METERPRETER, "GET",
         "/.env", None,
         "same attacker escalates → ENV decoy (credential_access)"),
    Step("decoy", IP_RU, "Russia", UA_NIKTO, JA3_NIKTO, "GET",
         "/wp-admin/", None,
         "nikto JA3 + UA → WP-ADMIN decoy"),
    Step("decoy", IP_CN, "China", UA_PYREQUESTS, JA3_PYREQUESTS, "POST",
         "/api/debug/",
         "id=1 UNION SELECT username,password FROM users-- ",
         "python-requests, UNION SELECT in body → API decoy (sql_injection)"),
    Step("canary", IP_NL, "Netherlands", UA_CURL, JA3_CURL, "GET",
         "", None,
         "canary token trip-wire fires (canary HoneyEvent + immediate alert)"),
    Step("decoy", IP_US, "United States", UA_MASSCAN, "", "GET",
         "/wp-admin/", None,
         "masscan UA only (no stable JA3) → WP-ADMIN decoy"),
]

# Filler probes used to pad the wave up to --count. Spread across IPs, tools and
# techniques so the dashboard and map keep changing during a recording.
_FILLER_STEPS: list[Step] = [
    Step("decoy", IP_RU, "Russia", UA_NUCLEI, "", "GET",
         "/api/debug/?file=..%2f..%2f..%2f..%2fetc%2fpasswd", None,
         "nuclei UA, path traversal → API decoy"),
    Step("decoy", IP_CN, "China", UA_PYREQUESTS, JA3_PYREQUESTS, "GET",
         "/.env", None,
         "python-requests grabbing /.env (credential_access)"),
    Step("decoy", IP_US, "United States", UA_GO, "", "GET",
         "/admin/", None,
         "go-http-client probing the admin login"),
    Step("decoy", IP_DE, "Germany", UA_SQLMAP, JA3_METERPRETER, "GET",
         "/wp-admin/?s=1%27%20OR%20SLEEP%285%29%23", None,
         "sqlmap time-based SQLi on WP search"),
    Step("decoy", IP_NL, "Netherlands", UA_NIKTO, JA3_NIKTO, "GET",
         "/admin/", None,
         "nikto sweeping the admin login"),
    Step("decoy", IP_US, "United States", UA_CURL, JA3_CURL, "GET",
         "/.env", None,
         "curl pulling /.env"),
    Step("decoy", IP_CN, "China", UA_MASSCAN, "", "GET",
         "/wp-admin/", None,
         "masscan banner-grabbing /wp-admin/"),
    Step("decoy", IP_RU, "Russia", UA_PYREQUESTS, JA3_PYREQUESTS, "POST",
         "/api/debug/",
         "q=<script>alert(1)</script>",
         "python-requests, XSS payload in body → API decoy"),
]


class Command(BaseCommand):
    help = "Simulate scanner traffic (scenario wave by default; single shot with --ip)."

    def add_arguments(self, parser: ArgumentParser) -> None:
        # Scenario mode (the default when --ip is omitted).
        parser.add_argument(
            "--count",
            type=int,
            default=15,
            help="Scenario mode: how many events to simulate (default 15).",
        )
        parser.add_argument(
            "--watch",
            action="store_true",
            help="Scenario mode: pause between events so the dashboard updates one at a time.",
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=None,
            help="Seconds to pause between events under --watch (default: random 1-2s).",
        )
        parser.add_argument(
            "--settle",
            type=float,
            default=12.0,
            help="Scenario mode: seconds to wait for the worker to enrich before reporting.",
        )
        # Single-shot mode (triggered by passing --ip).
        parser.add_argument(
            "--ip",
            default=None,
            help="Single-shot mode: fire one request from this IP (instead of the scenario wave).",
        )
        parser.add_argument(
            "--path", default=DEFAULT_PATH, help=f"Single-shot decoy path (default {DEFAULT_PATH})."
        )
        parser.add_argument(
            "--ja3",
            default=DEFAULT_JA3,
            help="Single-shot JA3 hash for X-JA3-Hash; pass '' to send none.",
        )
        parser.add_argument(
            "--ua", dest="user_agent", default=DEFAULT_UA, help="Single-shot User-Agent header."
        )
        parser.add_argument(
            "--body",
            default=None,
            help="Single-shot request body (sent as POST) — handy to trip the TTP classifier.",
        )
        parser.add_argument(
            "--async",
            dest="use_celery",
            action="store_true",
            help="Single-shot: dispatch enrich_event to Celery instead of running it inline.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["ip"] is not None:
            self._run_single(options)
        else:
            self._run_scenario(options)

    # --- Scenario mode ----------------------------------------------------

    def _run_scenario(self, options: dict[str, Any]) -> None:
        count: int = options["count"]
        watch: bool = options["watch"]
        delay: float | None = options["delay"]
        settle: float = options["settle"]
        if count < 1:
            raise CommandError("--count must be at least 1.")

        steps = self._build_wave(count)
        self._ensure_scenario_routes()
        rule_baseline = self._ensure_alert_rules()

        self.stdout.write(self.style.MIGRATE_HEADING(f"Simulating {len(steps)} events"))
        if watch:
            self.stdout.write("  --watch on: pausing between events so the dashboard updates live.\n")

        created_ids: list[int] = []
        canary_token: CanaryToken | None = None
        ips: set[str] = set()
        for index, step in enumerate(steps, start=1):
            ips.add(step.ip)
            if step.kind == "canary":
                event, canary_token = self._fire_canary(step)
            else:
                event = self._fire_decoy(step)

            if event is None:
                self.stdout.write(
                    self.style.WARNING(f"  [{index:>2}/{len(steps)}] {step.ip} — no event (rate limited?)")
                )
            else:
                created_ids.append(event.id)
                self.stdout.write(
                    f"  [{index:>2}/{len(steps)}] {self.style.HTTP_INFO(step.method):<4} "
                    f"{step.ip:<16} {step.country:<14} → event #{event.id}: {step.note}"
                )
            if watch and index < len(steps):
                time.sleep(delay if delay is not None else random.uniform(1.0, 2.0))

        self._report_scenario(created_ids, sorted(ips), canary_token, rule_baseline, settle)

    def _build_wave(self, count: int) -> list[Step]:
        """Essentials first, then cycle fillers, truncated/extended to ``count``."""
        wave = list(_ESSENTIAL_STEPS)
        i = 0
        while len(wave) < count:
            wave.append(_FILLER_STEPS[i % len(_FILLER_STEPS)])
            i += 1
        return wave[:count]

    def _fire_decoy(self, step: Step) -> HoneyEvent | None:
        """Run one forged request through HoneyMiddleware; return the new event.

        We don't patch ``enrich_event.delay``: the middleware dispatches it to the
        real Celery worker, which is what drives the live dashboard. The created
        event is found by id (any event newer than the pre-fire max for this run).
        """
        factory = RequestFactory()
        if step.body is not None:
            request = factory.post(step.path, data=step.body, content_type="text/plain")
        else:
            request = factory.generic(step.method, step.path)
        request.META["REMOTE_ADDR"] = step.ip
        request.META["HTTP_USER_AGENT"] = step.user_agent
        if step.ja3:
            request.META["HTTP_X_JA3_HASH"] = step.ja3

        max_before = HoneyEvent.objects.aggregate(m=Max("id"))["m"] or 0
        HoneyMiddleware(_not_a_decoy)(request)
        return HoneyEvent.objects.filter(id__gt=max_before).order_by("id").first()

    def _fire_canary(self, step: Step) -> tuple[HoneyEvent | None, CanaryToken]:
        """Mint a fresh canary token and trip it, returning the logged event.

        A fresh token each run guarantees the trip fires (a token only trips once),
        so re-running the demo always lights the canary. ``record_trigger`` logs the
        canary HoneyEvent, dispatches enrichment, and fires canary alerts inline.
        """
        token = canary.generate_url_token(
            label=f"demo-canary {timezone.now():%Y-%m-%d %H:%M:%S}",
            created_by=self._canary_owner(),
        )
        factory = RequestFactory()
        request = factory.get(f"/canary/{token.token_id}/ping/")
        request.META["REMOTE_ADDR"] = step.ip
        request.META["HTTP_USER_AGENT"] = step.user_agent
        if step.ja3:
            request.META["HTTP_X_JA3_HASH"] = step.ja3

        event = canary.record_trigger(token, request)
        token.refresh_from_db()
        return event, token

    def _canary_owner(self) -> Any:
        """A user to own minted demo tokens (created_by is required)."""
        owner = User.objects.filter(is_superuser=True).order_by("pk").first()
        if owner is None:
            owner = User.objects.order_by("pk").first()
        if owner is None:
            owner = User.objects.create(username="honeydj-demo", is_active=False)
        return owner

    def _ensure_scenario_routes(self) -> None:
        """Create the DecoyRoutes the scenario hits, idempotently."""
        for path, decoy_type in SCENARIO_ROUTES:
            DecoyRoute.objects.get_or_create(
                path_pattern=path,
                defaults={
                    "decoy_type": decoy_type,
                    "response_template": "default",
                    "description": "simulate_scanner scenario route",
                    "is_active": True,
                    "priority": 10,
                },
            )

    def _ensure_alert_rules(self) -> dict[int, datetime | None]:
        """Create the demo AlertRules and return each rule's pre-run last_fired.

        The baseline lets the post-run report tell which rules actually fired
        during this run (their last_fired advanced).
        """
        baseline: dict[int, datetime | None] = {}
        for spec in DEMO_ALERT_RULES:
            rule, _ = AlertRule.objects.get_or_create(
                name=spec["name"],
                defaults={
                    "condition": spec["condition"],
                    "notifier_type": spec["notifier_type"],
                    "notifier_config": spec["notifier_config"],
                    "enabled": True,
                },
            )
            baseline[rule.pk] = rule.last_fired
        return baseline

    def _report_scenario(
        self,
        created_ids: list[int],
        ips: list[str],
        canary_token: CanaryToken | None,
        rule_baseline: dict[int, datetime | None],
        settle: float,
    ) -> None:
        """Wait for the worker to enrich, then report the state of the whole chain."""
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Pipeline report"))
        self.stdout.write(f"  events captured  : {len(created_ids)}")

        enriched = self._wait_for_enrichment(created_ids, settle)
        style = self.style.SUCCESS if enriched == len(created_ids) else self.style.WARNING
        self.stdout.write(style(f"  events enriched  : {enriched}/{len(created_ids)}"))
        if enriched < len(created_ids):
            self.stdout.write(
                "    (some still in the worker queue — re-check the admin in a moment.)"
            )

        self.stdout.write(self.style.MIGRATE_HEADING("  Attacker profiles"))
        any_geo = False
        for ip in ips:
            profile = AttackerProfile.objects.filter(ip=ip).first()
            if profile is None:
                self.stdout.write(self.style.WARNING(f"    {ip:<16} — no profile yet"))
                continue
            any_geo = any_geo or bool(profile.country_code)
            geo = profile.country or profile.country_code or "—"
            self.stdout.write(
                f"    {ip:<16} score={profile.threat_score:<3} "
                f"scanner={str(profile.is_known_scanner):<5} geo={geo:<14} "
                f"tags={profile.tags}"
            )
        if not any_geo:
            self.stdout.write(
                self.style.WARNING(
                    "    GeoIP returned nothing for every IP — the GeoLite2-City.mmdb is "
                    "likely missing (see GEOIP_PATH). The map will have no markers until "
                    "it's installed."
                )
            )

        self.stdout.write(self.style.MIGRATE_HEADING("  Canary token"))
        if canary_token is None:
            self.stdout.write(self.style.WARNING("    no canary step ran (count too small)"))
        elif canary_token.triggered:
            self.stdout.write(self.style.SUCCESS(
                f"    triggered=True at {canary_token.triggered_at:%H:%M:%S} "
                f"by {canary_token.trigger_ip}"
            ))
        else:
            self.stdout.write(self.style.ERROR("    triggered=False — canary trip did NOT fire"))

        self.stdout.write(self.style.MIGRATE_HEADING("  Alert rules fired"))
        fired_any = False
        for rule in AlertRule.objects.filter(pk__in=rule_baseline):
            before = rule_baseline.get(rule.pk)
            if rule.last_fired is not None and rule.last_fired != before:
                fired_any = True
                self.stdout.write(self.style.SUCCESS(
                    f"    ✓ {rule.name} (last_fired {rule.last_fired:%H:%M:%S})"
                ))
        if not fired_any:
            self.stdout.write(self.style.WARNING(
                "    no demo rule fired yet — if the worker is still draining, check "
                "the celery log for 'alert: rule … queued' / 'dispatch_alert'."
            ))

        self.stdout.write("")
        self.stdout.write(
            "Watch it live: open the dashboard, tail the worker "
            "(docker compose logs -f celery), and look for enrich_event + dispatch_alert."
        )

    def _wait_for_enrichment(self, created_ids: list[int], settle: float) -> int:
        """Poll until every created event is enriched, or ``settle`` seconds pass."""
        if not created_ids:
            return 0
        deadline = time.monotonic() + max(0.0, settle)
        while True:
            enriched = HoneyEvent.objects.filter(id__in=created_ids, enriched=True).count()
            if enriched == len(created_ids) or time.monotonic() >= deadline:
                return enriched
            time.sleep(0.5)

    # --- Single-shot mode (legacy) ---------------------------------------

    def _run_single(self, options: dict[str, Any]) -> None:
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
        decoupled here — ``_run_single`` decides whether to enrich inline or
        dispatch. We patch ``.delay`` on the task object itself, which is the same
        Celery singleton the middleware imported, so its dispatch is captured too.
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

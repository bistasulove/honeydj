# HoneyDjango — demo runbook

A copy-pasteable script for recording a screen capture of the full pipeline:
a simulated scanner wave hits the decoys, Celery enriches each event, the live
dashboard streams new rows, the canary trips, and alert rules fire.

The whole show is driven by one command:

```bash
docker compose exec web python manage.py simulate_scanner --watch --count 15
```

---

## 1. Prerequisites (once)

```bash
# From the repo root.
docker compose up -d            # web + celery + beat + postgres + redis
docker compose ps               # all services "Up" / "healthy"
```

You need an admin login to view the dashboard (it sits behind the obscured
admin prefix). Create one if you haven't:

```bash
docker compose exec web python manage.py createsuperuser
```

**Optional but recommended — the map needs GeoIP.** The Leaflet attack map only
plots attackers that GeoIP could locate. Without the MaxMind database the table,
stats and alerts all still work, but the map stays empty. To light up the map,
drop a `GeoLite2-City.mmdb` into the path `GEOIP_PATH` points at (default
`./geoip/`) and restart `web` + `celery`:

```bash
mkdir -p geoip
# copy GeoLite2-City.mmdb into ./geoip/  (free MaxMind GeoLite2 account)
docker compose restart web celery
```

> If you skip this, expect the report line *"GeoIP returned nothing for every IP
> … the map will have no markers"* and an empty map. Everything else is unaffected.

---

## 2. What to open before recording

Log into the admin first (so the dashboard doesn't bounce you to a login form),
then open these tabs. Default admin prefix is `hd-console` (`ADMIN_URL_SUFFIX`).

| Tab | URL | What it shows |
|-----|-----|---------------|
| **Dashboard** (record this) | http://localhost:8000/hd-console/dashboard/ | Live event table (streams over WebSocket), headline stats, attack map |
| Attacker profiles | http://localhost:8000/hd-console/profiles/attackerprofile/ | Threat scores, tags, `is_known_scanner` |
| Canary tokens | http://localhost:8000/hd-console/honeypot/canarytoken/ | `triggered` flips to ✓ |
| Alert rules | http://localhost:8000/hd-console/alerts/alertrule/ | `last_fired` timestamps update |

Optional second pane — tail the worker so viewers see enrichment + alerts fire:

```bash
docker compose logs -f celery
```

Keep the **Dashboard** tab focused for the recording. Hard-refresh it once
(Cmd/Ctrl-Shift-R) right before you start so the live table opens its WebSocket.

---

## 3. Run the simulation

```bash
docker compose exec web python manage.py simulate_scanner --watch --count 15
```

`--watch` pauses 1–2s between events so the dashboard updates one row at a time
(drop it to fire the whole wave instantly). `--count` sizes the wave.

The command is self-contained: it creates the decoy routes, two demo `AlertRule`s,
and a fresh canary token, then fires the wave and prints a pipeline report.

---

## 4. Expected visual sequence (what "working" looks like)

As the command prints each `[ n/15]` line:

1. **Live event table** (top of the dashboard) prepends a new row within ~1s of
   each printed line — IP, decoy type, threat score, tags. Rows appear newest-first
   and the list caps at 50.
2. **Stats strip** counters climb: *total events* and *unique attackers* tick up;
   the *top decoys* breakdown shifts as admin/env/wp-admin/api hits land. (Polls
   every 10s, so it lags the table slightly.)
3. **Attack map** drops a marker per geolocated attacker — *only if the GeoIP DB is
   installed* (see §1). Polls every 30s.
4. Around event 4–5 the **canary** trips: the Canary tokens admin shows
   `triggered=True`, and the worker log prints `canary: token … tripped`.
5. The **worker log** shows `enrich_event: done … scanner=True` and, for the
   Germany IP (`185.220.101.34`) and other known scanners, `alert: rule … queued`
   followed by `dispatch_alert: rule … `.

When the command finishes it prints a **Pipeline report**:

```
Pipeline report
  events captured  : 15
  events enriched  : 15/15
  Attacker profiles
    185.220.101.34   score=50  scanner=True  geo=Germany       tags=[...]
    ...
  Canary token
    triggered=True at HH:MM:SS by 80.80.80.80
  Alert rules fired
    ✓ Demo: canary token tripped
    ✓ Demo: known scanner detected
```

`events enriched : 15/15`, `triggered=True`, and at least one `✓` rule are the
green lights that the whole chain fired. (`geo=—` on every profile means the
GeoIP DB is missing — see §1.)

> **Note on alert delivery.** The demo rules POST to a placeholder webhook
> (`https://example.com/...`), so the worker logs `WebhookNotifier failed … 405`.
> That's expected: the alert *dispatched* (the point of the demo). Point the rule
> at a real Slack/webhook URL in the Alert rules admin to see a delivered alert.

---

## 5. Reset between takes

The wave appends to whatever is already there. For a clean recording, clear the
captured data first (this does **not** touch your superuser):

```bash
docker compose exec web python manage.py shell -c "
from apps.events.models import HoneyEvent
from apps.profiles.models import AttackerProfile
from apps.honeypot.models import CanaryToken
HoneyEvent.objects.all().delete()
AttackerProfile.objects.all().delete()
CanaryToken.objects.filter(label__startswith='demo-canary').delete()
print('cleared')
"
```

The demo `AlertRule`s and `DecoyRoute`s are created idempotently, so you can leave
them. Hard-refresh the dashboard after clearing.

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Dashboard redirects to a login page | Not logged in — log into the admin first. |
| Live table never updates | WebSocket didn't connect — hard-refresh the dashboard; check `web` (daphne) is up. |
| `events enriched : 0/15` in the report | Celery worker not running/draining — `docker compose ps`, `docker compose logs celery`. |
| Map is empty | GeoIP DB missing — install `GeoLite2-City.mmdb` (see §1). |
| Counters don't move | Stats poll is every 10s; give it a moment, or check the worker is enriching. |

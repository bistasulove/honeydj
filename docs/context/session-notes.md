# Session notes — 2026-06-22 (demoable end-to-end + simulate_scanner)

## What was built
- `apps/honeypot/management/commands/simulate_scanner.py` — added **scenario
  mode** (default when `--ip` omitted) alongside the preserved single-shot mode.
  Fires a curated wave through real `HoneyMiddleware`: 4+ decoy types, realistic
  scanner UAs/JA3s, SQLi in query+body, 3-5 public IPs (DE/RU/CN/NL/US), a fresh
  canary trip, and demo `AlertRule`s. Flags: `--count` (15), `--watch` (1-2s
  pacing, `--delay`), `--settle`. Auto-creates routes + 2 demo alert rules +
  canary token; prints a pipeline report.
- `tests/test_simulate_scanner.py` — +6 scenario tests (inline_pipeline fixture).
- `docs/DEMO.md` — copy-paste screen-recording runbook.
- `.gitignore` — added `geoip/*.mmdb` (license + size + staleness).

## Key decisions
- `--ip` present → single-shot (keeps 6 legacy tests); absent → scenario.
- Scenario dispatches to the **real Celery worker** so the live dashboard updates.
- Public DNS/Tor IPs chosen ONLY because GeoLite2 resolves them (TEST-NET won't).
- Command creates demo AlertRules itself (none existed) so dispatch_alert fires.
- GeoLite2 DB is NOT committed (MaxMind EULA, ~66MB, weekly updates).

## Verified live (full Docker stack)
enriched 15/15 ✓ · profiles scored + is_known_scanner ✓ · canary triggered ✓ ·
dispatch_alert ran in worker ✓ · WebSocket push confirmed cross-process ✓ ·
**GeoIP now installed at `geoip/GeoLite2-City.mmdb` → lookups resolve, profiles
geolocated, map markers render** ✓.

## Broken / incomplete
- Demo alert webhook is a placeholder → notifier logs 405; dispatch still fires
  (point a rule at a real Slack/webhook URL to see delivery).
- Older profiles enriched pre-GeoIP keep null geo unless re-seen (`_fill_geo`
  backfills empty fields on the next event). DEMO.md §5 resets demo data.
- No `geoipupdate`/cron yet to refresh the DB (manual download for now).

## Next task to resume from
Commit (`feat: scenario simulate_scanner + demo runbook`). Optionally wire up
`geoipupdate` for periodic GeoLite2 refresh.

## Gotchas
- 148 tests pass, 90.46% cov; ruff + mypy clean.
- geoip reader caches availability at process start — restart celery after
  installing the DB.
- enrich's `_broadcast` is on_commit — tests skip it without
  `django_capture_on_commit_callbacks`.

# Session notes — 2026-06-14

## What was built — live attack map dashboard
- `apps/dashboard/views.py` (new) — `MapDataView` (LoginRequired): last 500
  geolocated `AttackerProfile`s as GeoJSON, 30s server-side cache
  (`dashboard:map_data` key). `DashboardView` (LoginRequired TemplateView):
  headline counters (total events, unique attackers, top-5 decoy types).
- `apps/dashboard/templates/dashboard/` (new) — `base.html` (standalone shell,
  Tailwind/HTMX/Alpine/Leaflet via CDN), `map.html`, `partials/_stats.html`.
- `apps/dashboard/static/dashboard/` (new) — `map.js` (Leaflet island),
  `dashboard.css` (pulse animation).
- `apps/dashboard/urls.py` — `map` + `map_data` routes.
- `honeydj/urls.py` — dashboard mounted under the admin prefix
  (`/hd-{ADMIN_URL_SUFFIX}/dashboard/`), before `admin.site.urls`.
- `honeydj/settings/base.py` — `UNFOLD["SIDEBAR"]` nav (replaces auto app list);
  added "Live Map" link + the 3 model changelists.
- `apps/events/tasks.py` + `consumers.py` — added `lat`/`lon` to the enriched
  WebSocket payload so live hits can be plotted.

## Key decisions
- **Standalone shell, not embedded in unfold admin.** unfold is CRUD chrome; its
  flex layout broke Leaflet. Own shell = layout control + scalable (stable JSON
  endpoints, partials, static JS islands; "CDN now, build later").
- Map = config-driven JS island reading `data-*` attrs; no inline JS, so re-skin
  doesn't touch logic.

## Gotchas
- **Map glitch root cause:** Leaflet cached container size before layout settled.
  Fixed via `invalidateSize()` after first paint + on ResizeObserver.
- **Live pulse needs coords:** localhost/LAN IPs don't geolocate → null lat/lon →
  no marker. Test WS path via `group_send` shell with a public-IP row.
- Persistent dots come from the 30s poll, NOT the WS (pulse is ephemeral, 3s).
- Dashboard is login-required (`admin:login`), not staff-gated — revisit if
  non-staff users ever exist.

## Next task to resume from
Wire HTMX auto-refresh on `_stats.html` (hx-get + interval → stats partial) and
add a live event-table partial fed by the `/ws/events/` socket.

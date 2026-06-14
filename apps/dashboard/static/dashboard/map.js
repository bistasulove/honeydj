/*
 * Live attack map island.
 *
 * Self-contained: reads its config from the #attack-map element's data-*
 * attributes (URLs reversed by Django), so it carries no hardcoded paths and
 * the surrounding template can be re-skinned freely.
 *
 * Two data sources:
 *   - polled GeoJSON (cached server-side) -> persistent CircleMarkers
 *   - the /ws/events/ socket -> short-lived pulsing "live attack" markers
 *
 * The historic glitch (tiles half-loading, breaking on zoom) was Leaflet
 * caching the container size before the layout had settled. We fix that by
 * calling invalidateSize() once after first paint and again whenever the
 * container resizes.
 */
(function () {
  "use strict";

  var el = document.getElementById("attack-map");
  if (!el || typeof L === "undefined") {
    return;
  }

  var MAP_DATA_URL = el.dataset.mapDataUrl;
  var WS_PATH = el.dataset.wsPath || "/ws/events/";
  var REFRESH_MS = 30000;

  // --- map setup ---------------------------------------------------------
  var map = L.map(el, { worldCopyJump: true }).setView([20, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 18,
    attribution: "&copy; OpenStreetMap contributors",
  }).addTo(map);

  // Persistent profile markers, cleared and rebuilt on each poll.
  var profileLayer = L.layerGroup().addTo(map);

  // --- the sizing fix ----------------------------------------------------
  // Recompute size after first paint (container has its real height by then),
  // and keep it correct as the viewport/container changes.
  requestAnimationFrame(function () { map.invalidateSize(); });
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(function () { map.invalidateSize(); }).observe(el);
  } else {
    window.addEventListener("resize", function () { map.invalidateSize(); });
  }

  // --- helpers -----------------------------------------------------------
  function colourFor(score) {
    if (score > 70) return "#dc2626"; // red
    if (score >= 40) return "#f59e0b"; // amber
    return "#16a34a"; // green
  }

  function radiusFor(eventCount) {
    // Scale by hit volume but keep markers legible: clamp to [6, 20].
    return Math.max(6, Math.min(20, 6 + Math.sqrt(eventCount || 0) * 2));
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function popupHtml(props) {
    var tags = (props.tags && props.tags.length)
      ? props.tags.map(escapeHtml).join(", ") : "—";
    return "<strong>" + escapeHtml(props.ip) + "</strong><br>" +
      "Country: " + (escapeHtml(props.country) || "—") + "<br>" +
      "Events: " + escapeHtml(props.event_count) + "<br>" +
      "Threat: " + escapeHtml(props.threat_score) + "<br>" +
      "Last seen: " + escapeHtml(props.last_seen) + "<br>" +
      "Tags: " + tags;
  }

  // --- polled profiles ---------------------------------------------------
  function loadProfiles() {
    if (!MAP_DATA_URL) return;
    fetch(MAP_DATA_URL, { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : Promise.reject(resp.status); })
      .then(function (geojson) {
        profileLayer.clearLayers();
        (geojson.features || []).forEach(function (feature) {
          var coords = feature.geometry.coordinates; // [lon, lat]
          var props = feature.properties;
          var colour = colourFor(props.threat_score);
          L.circleMarker([coords[1], coords[0]], {
            radius: radiusFor(props.event_count),
            color: colour,
            fillColor: colour,
            fillOpacity: 0.6,
            weight: 1,
          }).bindPopup(popupHtml(props)).addTo(profileLayer);
        });
      })
      .catch(function (err) { console.error("map-data fetch failed:", err); });
  }

  loadProfiles();
  setInterval(loadProfiles, REFRESH_MS);

  // --- live attacks over WebSocket --------------------------------------
  function flashLiveAttack(lat, lon) {
    var icon = L.divIcon({
      className: "",
      html: '<div class="live-attack-pulse"></div>',
      iconSize: [14, 14],
    });
    var marker = L.marker([lat, lon], { icon: icon, interactive: false }).addTo(map);
    // CSS fade runs ~3s; drop the marker once it has finished.
    setTimeout(function () { map.removeLayer(marker); }, 3000);
  }

  function connectWebSocket() {
    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var ws = new WebSocket(scheme + "://" + window.location.host + WS_PATH);
    ws.onmessage = function (event) {
      try {
        var row = JSON.parse(event.data);
        if (row.lat !== null && row.lat !== undefined &&
            row.lon !== null && row.lon !== undefined) {
          flashLiveAttack(row.lat, row.lon);
        }
      } catch (err) {
        console.error("bad ws payload:", err);
      }
    };
    // Reconnect after a short delay if the socket drops.
    ws.onclose = function () { setTimeout(connectWebSocket, 5000); };
  }

  connectWebSocket();
})();

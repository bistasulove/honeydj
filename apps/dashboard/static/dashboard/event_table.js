/*
 * Live event table island.
 *
 * The HTMX WebSocket extension (hx-ext="ws" on the table section) owns the
 * connection to /ws/events/. But that socket carries JSON — not HTML — because
 * the live map (map.js) shares it and needs structured lat/lon. So rather than
 * let htmx swap raw HTML, we listen for htmx's `htmx:wsAfterMessage`, parse the
 * JSON, and build a row ourselves from the <template> in the partial.
 *
 * Config is read from data-* attributes on the section (the element that carries
 * ws-connect), so this file holds logic only — never markup or selectors baked
 * into JS strings:
 *   data-rows-target  CSS selector for the <tbody> rows are prepended to
 *   data-max-rows     hard cap on visible rows; oldest are trimmed past it
 */
(function () {
  "use strict";

  var TEMPLATE_ID = "event-row-template";
  var EMPTY_ROW_ID = "event-empty";

  // Colour the threat score by severity so the eye lands on the worst hits.
  function threatClass(score) {
    if (typeof score !== "number") return "text-slate-400";
    if (score >= 70) return "text-red-400";
    if (score >= 40) return "text-amber-400";
    return "text-slate-400";
  }

  function formatTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? "—" : d.toLocaleTimeString();
  }

  // Render tags as small pills; fall back to a dash when there are none.
  function renderTags(cell, tags) {
    cell.textContent = "";
    if (!Array.isArray(tags) || tags.length === 0) {
      cell.textContent = "—";
      cell.classList.add("text-slate-600");
      return;
    }
    tags.forEach(function (tag) {
      var pill = document.createElement("span");
      pill.className =
        "mr-1 inline-block rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300";
      pill.textContent = tag;
      cell.appendChild(pill);
    });
  }

  function buildRow(template, data) {
    var row = template.content.firstElementChild.cloneNode(true);
    var cells = {};
    row.querySelectorAll("[data-cell]").forEach(function (td) {
      cells[td.dataset.cell] = td;
    });

    cells.time.dataset.ts = data.timestamp || "";
    cells.time.textContent = formatTime(data.timestamp);
    cells.ip.textContent = data.ip || "—";
    cells.country.textContent = data.country || "—";
    cells.decoy_type.textContent = data.decoy_type || "—";

    var score = typeof data.threat_score === "number" ? data.threat_score : "—";
    cells.threat_score.textContent = score;
    cells.threat_score.classList.add(threatClass(data.threat_score));

    renderTags(cells.tags, data.tags);
    return row;
  }

  function prepend(section, data) {
    var template = document.getElementById(TEMPLATE_ID);
    var tbody = document.querySelector(section.dataset.rowsTarget);
    if (!template || !tbody) return;

    // Drop the "waiting for events" placeholder on the first real row.
    var empty = document.getElementById(EMPTY_ROW_ID);
    if (empty) empty.remove();

    tbody.insertBefore(buildRow(template, data), tbody.firstChild);

    // Trim oldest rows so the DOM (and memory) stay bounded.
    var max = parseInt(section.dataset.maxRows, 10) || 50;
    while (tbody.children.length > max) {
      tbody.removeChild(tbody.lastElementChild);
    }
  }

  // htmx fires this on the element carrying ws-connect for every WS message.
  document.body.addEventListener("htmx:wsAfterMessage", function (evt) {
    var section = evt.target;
    if (!section || !section.dataset || !section.dataset.rowsTarget) return;

    var data;
    try {
      data = JSON.parse(evt.detail.message);
    } catch (e) {
      return; // Not a JSON row (e.g. a control frame) — ignore.
    }
    prepend(section, data);
  });

  // Reformat server-seeded rows through the same formatter as live rows, so the
  // clock style is identical no matter who rendered the row (the server text is
  // a no-JS fallback; the ISO timestamp lives in data-ts). Runs once on load —
  // this script is deferred, so the DOM is already parsed.
  document.querySelectorAll("td[data-cell='time'][data-ts]").forEach(function (td) {
    if (td.dataset.ts) td.textContent = formatTime(td.dataset.ts);
  });
})();

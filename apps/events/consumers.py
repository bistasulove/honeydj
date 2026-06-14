"""WebSocket consumer that fans enriched honeypot events out to dashboards.

A single channel group, ``events``, carries every enriched event. The
enrichment Celery task broadcasts to this group after it commits (see
``apps/events/tasks.py``); this consumer subscribes connected dashboard
sessions to the group and forwards a trimmed payload to the browser.

Only the handful of fields the live table row needs are sent to the client —
never the full event, which may carry large headers or request bodies.
"""

import json
import logging
from typing import Any

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

EVENTS_GROUP = "events"

# Allowlist of fields forwarded to the browser. Kept deliberately small to keep
# WebSocket payloads tiny; anything not listed here is dropped before sending.
CLIENT_FIELDS = (
    "id",
    "ip",
    "path",
    "decoy_type",
    "country",
    "threat_score",
    "tags",
    "timestamp",
    # Coordinates drive the live map's pulsing "new attack" marker; may be null
    # when GeoIP couldn't locate the IP, in which case the map skips the marker.
    "lat",
    "lon",
)


class EventConsumer(AsyncWebsocketConsumer):  # type: ignore[misc]
    """Push enriched events to every connected dashboard client."""

    async def connect(self) -> None:
        await self.channel_layer.group_add(EVENTS_GROUP, self.channel_name)
        await self.accept()
        logger.debug("EventConsumer connected: %s", self.channel_name)

    async def disconnect(self, code: int) -> None:
        await self.channel_layer.group_discard(EVENTS_GROUP, self.channel_name)
        logger.debug("EventConsumer disconnected: %s (code=%s)", self.channel_name, code)

    async def event_enriched(self, event: dict[str, Any]) -> None:
        """Handle an ``event.enriched`` group message; forward a trimmed row.

        ``event`` is the dict sent by ``channel_layer.group_send``; the enriched
        row lives under the ``row`` key. We project it onto ``CLIENT_FIELDS`` so
        the client only ever sees what the table needs.
        """
        row = event.get("row", {})
        payload = {field: row.get(field) for field in CLIENT_FIELDS}
        await self.send(text_data=json.dumps(payload))

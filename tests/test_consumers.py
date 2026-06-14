"""Tests for the events WebSocket push layer (apps/events/consumers.py).

The scenarios drive ``WebsocketCommunicator`` inside a single ``async_to_sync``
call so connect/send/receive/disconnect all share one event loop. An in-memory
channel layer stands in for Redis, so these run without external services.
"""

import pytest
from asgiref.sync import async_to_sync
from channels.layers import channel_layers, get_channel_layer
from channels.testing import WebsocketCommunicator

from apps.events.consumers import EVENTS_GROUP, EventConsumer

# Channels runs close_old_connections() on every dispatch, which touches the DB,
# so the consumer tests need DB access enabled even though they store nothing.
pytestmark = pytest.mark.django_db

# A broadcast row carrying extra fields the consumer must drop before sending.
FULL_ROW = {
    "id": 42,
    "ip": "203.0.113.5",
    "path": "/wp-admin/",
    "method": "POST",  # not in CLIENT_FIELDS — must be stripped
    "decoy_type": "wpAdmin",
    "country": "Russia",
    "threat_score": 60,
    "tags": ["sql_injection"],
    "timestamp": "2026-06-14T00:00:00+00:00",
    "lat": 55.7522,  # forwarded — drives the live map marker
    "lon": 37.6156,
    "secret": "must not leak",  # not in CLIENT_FIELDS — must be stripped
}
TRIMMED_ROW = {
    "id": 42,
    "ip": "203.0.113.5",
    "path": "/wp-admin/",
    "decoy_type": "wpAdmin",
    "country": "Russia",
    "threat_score": 60,
    "tags": ["sql_injection"],
    "timestamp": "2026-06-14T00:00:00+00:00",
    "lat": 55.7522,
    "lon": 37.6156,
}


@pytest.fixture
def in_memory_layer(settings):
    """Swap the Redis channel layer for an in-process one — no Redis needed.

    The channel-layer manager caches backends by alias, so we clear that cache
    on the way in and out to make sure the consumer and the test share the same
    in-memory layer instance.
    """
    settings.CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
    channel_layers.backends.clear()
    yield get_channel_layer()
    channel_layers.backends.clear()


def test_connect_joins_events_group(in_memory_layer):
    async def scenario():
        communicator = WebsocketCommunicator(EventConsumer.as_asgi(), "/ws/events/")
        connected, _ = await communicator.connect()
        assert connected
        # The consumer's channel is now a member of the "events" group.
        assert in_memory_layer.groups.get(EVENTS_GROUP)
        await communicator.disconnect()

    async_to_sync(scenario)()


def test_group_message_is_forwarded_trimmed(in_memory_layer):
    async def scenario():
        communicator = WebsocketCommunicator(EventConsumer.as_asgi(), "/ws/events/")
        connected, _ = await communicator.connect()
        assert connected

        await in_memory_layer.group_send(
            EVENTS_GROUP, {"type": "event.enriched", "row": FULL_ROW}
        )
        payload = await communicator.receive_json_from()

        # Only allowlisted fields reach the client; method/secret are dropped.
        assert payload == TRIMMED_ROW
        await communicator.disconnect()

    async_to_sync(scenario)()


def test_disconnect_leaves_group_cleanly(in_memory_layer):
    async def scenario():
        communicator = WebsocketCommunicator(EventConsumer.as_asgi(), "/ws/events/")
        connected, _ = await communicator.connect()
        assert connected

        await communicator.disconnect()

        # Having left the group, a later broadcast is never queued for this client.
        await in_memory_layer.group_send(
            EVENTS_GROUP, {"type": "event.enriched", "row": FULL_ROW}
        )
        assert await communicator.receive_nothing() is True

    async_to_sync(scenario)()

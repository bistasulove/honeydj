from django.urls import URLPattern, path

from apps.events.consumers import EventConsumer

websocket_urlpatterns: list[URLPattern] = [
    path("ws/events/", EventConsumer.as_asgi()),
]

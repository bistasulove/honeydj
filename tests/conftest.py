import pytest
from django.core.cache import cache

from apps.honeypot import middleware


@pytest.fixture(autouse=True)
def reset_route_cache():
    """The route cache is module-level global state; reset it around each test."""
    middleware._route_cache = []
    middleware._regex_cache = {}
    middleware._cache_loaded_at = None
    yield
    middleware._route_cache = []
    middleware._regex_cache = {}
    middleware._cache_loaded_at = None


@pytest.fixture(autouse=True)
def isolated_cache(settings):
    """Use an in-memory cache so rate-limit tests don't need Redis and don't leak."""
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "honeydj-tests",
        }
    }
    cache.clear()
    yield
    cache.clear()

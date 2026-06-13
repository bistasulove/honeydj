"""Threat-intelligence feed adapters.

Each adapter wraps a single external reputation service behind a small,
typed interface so the enrichment task never touches HTTP details directly.
Adapters degrade gracefully: a missing API key or a network failure returns
``None`` rather than raising, so enrichment never fails on feed data alone.
"""

"""Django admin (django-unfold) for the honeypot intelligence console.

HoneyEvent and AttackerProfile are immutable captures: every field is
read-only and rows cannot be created or deleted from the admin. DecoyRoute is
the one operator-editable model — staff add and tune decoy paths here.
"""

from typing import Any

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.html import format_html, format_html_join
from unfold.admin import ModelAdmin
from unfold.decorators import display

from apps.events.models import HoneyEvent
from apps.honeypot.models import DecoyRoute
from apps.profiles.models import AttackerProfile


def _threat_badge(score: int | None) -> Any:
    """Render a 0-100 threat score as a coloured pill: red >70, amber 40-70,
    green <40. Returns a dash when the score is unknown (no profile yet)."""
    if score is None:
        return "—"
    if score > 70:
        bg, fg = "#fee2e2", "#991b1b"  # red
    elif score >= 40:
        bg, fg = "#fef3c7", "#92400e"  # amber
    else:
        bg, fg = "#dcfce7", "#166534"  # green
    return format_html(
        '<span style="display:inline-block;min-width:2rem;text-align:center;'
        "padding:2px 8px;border-radius:9999px;font-weight:600;font-size:12px;"
        'background:{};color:{};">{}</span>',
        bg,
        fg,
        score,
    )


def _tags_pills(tags: list[str] | None) -> Any:
    """Render an attacker's TTP tags as a row of small pills."""
    if not tags:
        return "—"
    return format_html_join(
        "",
        '<span style="display:inline-block;padding:1px 6px;margin:1px;'
        "border-radius:9999px;font-size:11px;background:#e0e7ff;"
        'color:#3730a3;">{}</span>',
        ((tag,) for tag in tags),
    )


@admin.register(HoneyEvent)
class HoneyEventAdmin(ModelAdmin):  # type: ignore[misc]  # unfold ships no stubs
    list_display = (
        "timestamp",
        "ip",
        "path",
        "decoy_type",
        "country",
        "threat_score",
        "tags_display",
    )
    list_filter = ("decoy_type", "enriched", "timestamp")
    search_fields = ("ip", "path", "user_agent")
    ordering = ("-timestamp",)
    date_hierarchy = "timestamp"
    list_per_page = 50
    readonly_fields = (
        "ip",
        "path",
        "method",
        "headers",
        "body",
        "ja3_hash",
        "user_agent",
        "decoy_type",
        "timestamp",
        "attacker",
        "enriched",
    )

    def get_queryset(self, request: HttpRequest) -> QuerySet[HoneyEvent]:
        # Pull the related profile so country/threat_score/tags don't N+1.
        qs: QuerySet[HoneyEvent] = super().get_queryset(request)
        return qs.select_related("attacker")

    @display(description="Country", ordering="attacker__country")  # type: ignore[misc]
    def country(self, obj: HoneyEvent) -> str:
        return (obj.attacker.country or "—") if obj.attacker else "—"

    @display(description="Threat", ordering="attacker__threat_score")  # type: ignore[misc]
    def threat_score(self, obj: HoneyEvent) -> Any:
        return _threat_badge(obj.attacker.threat_score if obj.attacker else None)

    @display(description="Tags")  # type: ignore[misc]
    def tags_display(self, obj: HoneyEvent) -> Any:
        return _tags_pills(obj.attacker.tags if obj.attacker else None)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(
        self, request: HttpRequest, obj: HoneyEvent | None = None
    ) -> bool:
        return False


@admin.register(AttackerProfile)
class AttackerProfileAdmin(ModelAdmin):  # type: ignore[misc]  # unfold ships no stubs
    list_display = (
        "ip",
        "country",
        "org",
        "threat_score",
        "event_count",
        "first_seen",
        "last_seen",
        "tags_display",
        "is_known_scanner",
    )
    list_filter = ("country_code", "is_known_scanner")
    search_fields = ("ip", "org", "asn")
    ordering = ("-threat_score",)
    readonly_fields = (
        "ip",
        "asn",
        "org",
        "country_code",
        "country",
        "city",
        "lat",
        "lon",
        "first_seen",
        "last_seen",
        "event_count",
        "raw_threat_score",
        "tags",
        "is_known_scanner",
    )

    @display(description="Threat", ordering="threat_score")  # type: ignore[misc]
    def threat_score(self, obj: AttackerProfile) -> Any:
        return _threat_badge(obj.threat_score)

    @display(description="Score")  # type: ignore[misc]
    def raw_threat_score(self, obj: AttackerProfile) -> int:
        # Plain numeric value for the read-only detail view (the list column
        # `threat_score` is a coloured badge and shadows the model field).
        return obj.threat_score

    @display(description="Tags")  # type: ignore[misc]
    def tags_display(self, obj: AttackerProfile) -> Any:
        return _tags_pills(obj.tags)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(
        self, request: HttpRequest, obj: AttackerProfile | None = None
    ) -> bool:
        return False


@admin.register(DecoyRoute)
class DecoyRouteAdmin(ModelAdmin):  # type: ignore[misc]  # unfold ships no stubs
    list_display = ("path_pattern", "decoy_type", "is_active", "priority")
    list_editable = ("is_active", "priority")
    list_filter = ("decoy_type", "is_active", "is_regex")
    search_fields = ("path_pattern", "description")

"""Seed the six default decoy routes for well-known attack paths.

Idempotent: keyed on ``path_pattern`` via ``update_or_create`` so re-running
refreshes the canonical rows without creating duplicates.
"""

from typing import Any

from django.core.management.base import BaseCommand

from apps.honeypot.models import DecoyRoute

DEFAULT_ROUTES: list[dict[str, Any]] = [
    {
        "path_pattern": "/wp-admin/",
        "decoy_type": DecoyRoute.DecoyType.WP_ADMIN,
        "response_template": "wp_login",
        "description": "WordPress admin login probe",
        "priority": 90,
    },
    {
        "path_pattern": r"/\.env$",
        "is_regex": True,
        "decoy_type": DecoyRoute.DecoyType.ENV,
        "response_template": "dotenv",
        "description": "Leaked .env secrets probe",
        "priority": 100,
    },
    {
        "path_pattern": "/phpinfo.php",
        "decoy_type": DecoyRoute.DecoyType.CUSTOM,
        "response_template": "phpinfo",
        "description": "phpinfo() disclosure probe",
        "priority": 70,
    },
    {
        "path_pattern": "/admin/",
        "decoy_type": DecoyRoute.DecoyType.ADMIN,
        "response_template": "admin_login",
        "description": "Generic admin panel probe",
        "priority": 80,
    },
    {
        "path_pattern": "/api/debug/",
        "decoy_type": DecoyRoute.DecoyType.API,
        "response_template": "api_debug",
        "description": "Debug API endpoint probe",
        "priority": 60,
    },
    {
        "path_pattern": "/phpMyAdmin/",
        "decoy_type": DecoyRoute.DecoyType.CUSTOM,
        "response_template": "phpmyadmin",
        "description": "phpMyAdmin login probe",
        "priority": 75,
    },
]


class Command(BaseCommand):
    help = "Seed the six default DecoyRoute rows for common attack paths."

    def handle(self, *args: Any, **options: Any) -> None:
        created = 0
        updated = 0
        for route in DEFAULT_ROUTES:
            defaults = {k: v for k, v in route.items() if k != "path_pattern"}
            _, was_created = DecoyRoute.objects.update_or_create(
                path_pattern=route["path_pattern"],
                defaults=defaults,
            )
            if was_created:
                created += 1
            else:
                updated += 1
        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded decoy routes: {created} created, {updated} updated."
            )
        )

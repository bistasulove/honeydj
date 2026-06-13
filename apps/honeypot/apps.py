from django.apps import AppConfig


class HoneypotConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.honeypot"
    verbose_name = "Honeypot"

    def ready(self) -> None:
        from django.db.models.signals import post_delete, post_save

        from apps.honeypot.middleware import invalidate_route_cache
        from apps.honeypot.models import DecoyRoute

        post_save.connect(invalidate_route_cache, sender=DecoyRoute)
        post_delete.connect(invalidate_route_cache, sender=DecoyRoute)

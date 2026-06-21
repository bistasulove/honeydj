from django.urls import path

from apps.honeypot import views
from apps.honeypot.admin_views import CanaryTokenCreateView

app_name = "honeypot"

# Well-known attack paths routed straight to a decoy view. Mounted at the site
# root (see honeydj/urls.py). None of these collide with the admin/, api/ or
# dashboard/ prefixes. Most real-world probes are caught earlier by
# HoneyMiddleware via DecoyRoute rows; these explicit routes are the fallback
# for paths with no DecoyRoute configured.
urlpatterns = [
    path(".env", views.FakeDotEnvView.as_view(), name="fake_env"),
    path("wp-admin/", views.FakeWpAdminView.as_view(), name="fake_wp_admin"),
    path("wp-login.php", views.FakeWpAdminView.as_view(), name="fake_wp_login"),
    path("administrator/", views.FakeAdminView.as_view(), name="fake_admin"),
    path("api/debug/", views.FakeApiDebugView.as_view(), name="fake_api_debug"),
    # Canary trip-wire. Public and unauthenticated — an attacker who finds the
    # token must be able to hit it. The UUID is the token's lookup key.
    path(
        "canary/<uuid:token_id>/ping/",
        views.CanaryPingView.as_view(),
        name="canary_ping",
    ),
    # Staff-only token minting (LoginRequiredMixin gates it). Linked from the
    # CanaryToken admin "Create Token" button.
    path(
        "canary/create/",
        CanaryTokenCreateView.as_view(),
        name="canary_create",
    ),
]

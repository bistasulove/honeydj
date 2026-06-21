"""Operator-facing view for minting canary tokens.

Unlike :class:`apps.honeypot.views.CanaryPingView` (public, attacker-facing),
this is staff-only: it's how an operator creates a new URL token to plant. It's
reached from the "Create Token" button on the CanaryToken admin changelist.

``GET`` renders a minimal self-posting form; ``POST`` creates the token and
returns JSON carrying the new ``token_id`` and its full ping URL, so the form's
fetch (or a scripted caller) gets a copy-pasteable trip-wire link back.
"""

import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import reverse_lazy
from django.views import View

from apps.honeypot import canary
from apps.honeypot.models import CanaryToken

logger = logging.getLogger(__name__)


class CanaryTokenCreateView(LoginRequiredMixin, View):
    """Create a URL canary token (staff only).

    Behind the admin login (``LoginRequiredMixin``) — an anonymous request is
    redirected there rather than being allowed to mint tokens.
    """

    login_url = reverse_lazy("admin:login")

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse(_FORM_HTML)

    def post(self, request: HttpRequest) -> JsonResponse:
        label = (request.POST.get("label") or "").strip()
        # Only URL tokens are wired up so far; reject anything else explicitly
        # rather than silently minting the wrong type.
        token_type = request.POST.get("token_type", CanaryToken.TokenType.URL)
        if not label:
            return JsonResponse({"error": "label is required"}, status=400)
        if token_type != CanaryToken.TokenType.URL:
            return JsonResponse(
                {"error": "only url tokens are supported"}, status=400
            )

        user = request.user
        # LoginRequiredMixin guarantees an authenticated User reached the body.
        assert isinstance(user, User)
        token = canary.generate_url_token(label, user)
        return JsonResponse(
            {
                "token_id": str(token.token_id),
                "ping_url": canary.get_canary_url(token, request),
            },
            status=201,
        )


# Minimal self-posting form. Submits via fetch() so the JSON response (token_id +
# ping URL) can be shown inline without a page reload, then offered to copy. The
# ping URL is injected as a text node (not innerHTML) so a label echoed back can
# never inject markup.
_FORM_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Create canary token</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; }
  label { display:block; margin: .75rem 0 .25rem; font-weight: 600; }
  input, select, button { font-size: 1rem; padding: .5rem; width: 100%; box-sizing: border-box; }
  button { margin-top: 1rem; cursor: pointer; }
  #result { margin-top: 1.5rem; word-break: break-all; }
  code { background:#f3f4f6; padding:.2rem .4rem; border-radius:.25rem; }
</style></head>
<body>
<h1>Create canary token</h1>
<form id="f">
  <label for="label">Label</label>
  <input id="label" name="label" required placeholder="e.g. leaked-prod-credentials.txt">
  <label for="token_type">Type</label>
  <select id="token_type" name="token_type"><option value="url">URL</option></select>
  <button type="submit">Create token</button>
</form>
<div id="result"></div>
<script>
function cookie(name) {
  return document.cookie.split('; ').find(c => c.startsWith(name + '='))?.split('=')[1] ?? '';
}
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await fetch('', {
    method: 'POST',
    headers: { 'X-CSRFToken': cookie('csrftoken') },
    body: new FormData(e.target),
  });
  const data = await res.json();
  const out = document.getElementById('result');
  if (data.ping_url) {
    out.textContent = '';
    const code = document.createElement('code');
    code.textContent = data.ping_url;
    out.append('Token created. Ping URL: ', code);
  } else {
    out.textContent = 'Error: ' + (data.error || 'unknown');
  }
});
</script>
</body></html>"""

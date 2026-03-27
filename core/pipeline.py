from django.conf import settings
from social_core.exceptions import AuthForbidden
from django.contrib import messages

def enforce_institution_domain(strategy, details, backend, **kwargs):
    email = (details.get("email") or "").strip().lower()
    allowed = strategy.setting("ALLOWED_EMAIL_DOMAIN", "cecar.edu.co")
    if not email.endswith("@" + allowed):
        messages.error(strategy.request, f"Solo se permiten cuentas @{allowed}")
        raise AuthForbidden(backend)




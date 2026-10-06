"""Make the security switch visible to every template (for the top banner)."""

from django.conf import settings


def security_mode(request):
    return {
        "secure_mode": settings.SECURE_MODE,
        "debug_mode": settings.DEBUG,
    }

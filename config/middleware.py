"""
Middleware used by demo 2 (stored XSS).

A Content-Security-Policy header tells the browser which sources of script,
style and images it is allowed to run. It is a *second line of defence*: if an
attacker does manage to inject a <script> tag into a page, a strict CSP makes
the browser refuse to run it.

This is not a substitute for escaping output. It is a safety net for the day
you get the escaping wrong.
"""

from django.conf import settings


class ContentSecurityPolicyMiddleware:
    """Attach a Content-Security-Policy header - in SECURE_MODE only."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if settings.SECURE_MODE:
            # "script-src 'self'" blocks inline <script> blocks and
            # javascript: URLs. An XSS payload pasted into a forum post is
            # inline script, so the browser refuses to execute it and logs a
            # CSP violation in the developer console.
            response["Content-Security-Policy"] = settings.CONTENT_SECURITY_POLICY

            # Small extras that cost nothing and are good habits:
            response["Referrer-Policy"] = "same-origin"
            response["X-Content-Type-Options"] = "nosniff"
        else:
            # BYPASS: no CSP header at all. The browser will happily run any
            # script it finds in the HTML, including one a student pasted into
            # a forum post.
            pass

        return response

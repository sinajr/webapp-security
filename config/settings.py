"""
Django settings for the web-security teaching lab.

=============================================================================
  WARNING: THIS PROJECT IS DELIBERATELY INSECURE.
  It exists to teach web vulnerabilities in a classroom. Run it on localhost
  only. Never deploy it, never expose it to a network, never put real data in
  it. See README.md.
=============================================================================

The whole lab is controlled by ONE switch: SECURE_MODE.

    SECURE_MODE=0  (default)  -> vulnerable code paths are used
    SECURE_MODE=1             -> fixed code paths are used

Every demo in forum/views.py branches on `settings.SECURE_MODE`, so you can
run the exact same attack twice and watch it stop working.

THE BIG LESSON: Django is secure by default. Almost every vulnerability in
this lab required us to go out of our way to *switch off* a protection Django
already gave us for free. Look for the "BYPASS:" comments below.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env_flag(name, default=False):
    """Read a boolean from the environment ('1', 'true', 'yes' -> True)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# THE SWITCH
# ---------------------------------------------------------------------------
SECURE_MODE = env_flag("SECURE_MODE", default=False)


# ---------------------------------------------------------------------------
# Demo 5: security misconfiguration
# ---------------------------------------------------------------------------
# DEBUG=True in production is one of the most common real-world mistakes.
# Django's own error page is a fantastic debugging tool *and* a fantastic gift
# to an attacker: it prints your settings, your installed apps, your file
# paths and a full stack trace. Visit /misconfig/ in both modes to see it.
#
# BYPASS: `django-admin startproject` ships DEBUG=True because that is right
# for local development. The mistake is shipping it that way. In SECURE_MODE
# we do what a real deployment must do.
DEBUG = not SECURE_MODE

# With DEBUG=False Django refuses requests for hosts it does not recognise,
# which stops Host-header poisoning. We list only localhost - as it should be.
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]

# A real deployment would read this from the environment and never commit it.
# Hard-coding a secret key in a file that goes into git is itself a classic
# misconfiguration - anyone with the key can forge session cookies and
# password-reset tokens.
SECRET_KEY = "django-insecure-teaching-lab-key-do-not-use-anywhere-real"


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "forum",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # Django's CSRF protection is ON for every view by default. Demo 4 shows
    # what happens when a single view opts out with @csrf_exempt.
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Demo 2: adds a Content-Security-Policy header, but only in SECURE_MODE.
    "config.middleware.ContentSecurityPolicyMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # Makes `secure_mode` available in every template so the
                # banner and the demo pages can react to the switch.
                "forum.context_processors.security_mode",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
# Django hashes passwords with PBKDF2 by default and never stores them in
# plain text. Demo 1 contrasts this with a fake "legacy" table that does store
# plain text - which is why the SQL injection there is so damaging.
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

LOGIN_URL = "/login/"


# ---------------------------------------------------------------------------
# Internationalization / static files
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = []

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# Demo 2: cookie hardening
# ---------------------------------------------------------------------------
# Django's defaults are already SESSION_COOKIE_HTTPONLY = True and
# SESSION_COOKIE_SAMESITE = "Lax". We have to deliberately weaken them to make
# the stored-XSS demo interesting.
#
# HttpOnly=True means JavaScript cannot read the cookie via document.cookie,
# so an injected <script> cannot steal the victim's session.
# SameSite="Lax" means the browser will not attach the cookie to most
# cross-site requests, which blunts CSRF (demo 4) as well.
if SECURE_MODE:
    SESSION_COOKIE_HTTPONLY = True      # Django's default. Blocks cookie theft via XSS.
    SESSION_COOKIE_SAMESITE = "Lax"     # Django's default. Blunts cross-site requests.
    CSRF_COOKIE_HTTPONLY = False        # Must stay readable: the JS-free form posts it.
    CSRF_COOKIE_SAMESITE = "Lax"
    X_FRAME_OPTIONS = "DENY"            # No framing at all -> no clickjacking.
else:
    # BYPASS: we are switching OFF two protections Django enabled for us.
    SESSION_COOKIE_HTTPONLY = False     # document.cookie now leaks the session id.
    SESSION_COOKIE_SAMESITE = None      # No SameSite attribute is sent at all.
    CSRF_COOKIE_SAMESITE = None
    X_FRAME_OPTIONS = "SAMEORIGIN"      # Django's default.

# Note: the *_COOKIE_SECURE and SECURE_SSL_REDIRECT settings that
# `manage.py check --deploy` asks for are intentionally left off, because this
# lab runs over plain HTTP on localhost. On a real site they must be on.


# ---------------------------------------------------------------------------
# Demo 2: Content-Security-Policy
# ---------------------------------------------------------------------------
# Read by config/middleware.py. "'self'" means: only load scripts and styles
# that came from this site's own URLs. Inline <script> tags - exactly what a
# stored-XSS payload is - are refused by the browser.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)

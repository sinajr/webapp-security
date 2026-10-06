"""
Every vulnerability demo in this lab lives in this file.

HOW TO READ THIS FILE
---------------------
Each view that demonstrates a vulnerability is split in two by

    if settings.SECURE_MODE:
        ... the fix ...
    else:
        ... the vulnerable version ...

Run the app with SECURE_MODE=0 (the default), perform the attack, then restart
with SECURE_MODE=1 and perform exactly the same attack again. Nothing else
changes - only the branch that runs.

Pay attention to the comments marked "BYPASS". They mark the places where the
vulnerable code has to go *out of its way* to switch off a protection that
Django gave us for free. That is the main lesson of this lab: you rarely have
to add security to a Django app, but it is easy to remove it by accident.
"""

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from .models import Course, Grade, Message, Post, Thread


# ===========================================================================
# Home and general pages
# ===========================================================================

def home(request):
    courses = Course.objects.select_related("teacher").all()
    return render(request, "forum/home.html", {"courses": courses})


def demos(request):
    """The /demos page - one paragraph per vulnerability plus repro steps."""
    return render(request, "forum/demos.html")


# ===========================================================================
# DEMO 1 - SQL INJECTION ON LOGIN
# ===========================================================================
#
# The attack: type   ' OR '1'='1' --   into the username box, anything into
# the password box, and you are logged in as the first user in the table
# (which we seeded as the teacher).
#
# Why it works: the vulnerable branch pastes your typing straight into a SQL
# string. The database cannot tell the difference between "data the programmer
# meant" and "SQL the attacker typed", so your quote closes the string early
# and the rest of your input becomes part of the query.
#
# Why the fix works: the secure branch never builds SQL by hand. Django's ORM
# sends the query and the values to the database separately (a "parameterised
# query"), so the value ' OR '1'='1' -- is looked up as a *username* that
# happens to contain punctuation. It matches nothing.
# ===========================================================================

def login_view(request):
    error = None
    executed_sql = None  # shown on the page so students can see the damage

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        if settings.SECURE_MODE:
            # ---------------- SECURE ----------------
            # authenticate() does two things for us:
            #   1. It looks the user up through the ORM. The ORM *always*
            #      parameterises, so SQL injection is structurally impossible
            #      here - we could not write this bug if we tried.
            #   2. It compares the password against a salted PBKDF2 hash with
            #      a constant-time comparison. We never see, store or log the
            #      plain-text password.
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("home")
            error = "Invalid username or password."

        else:
            # ---------------- VULNERABLE ----------------
            # BYPASS: we deliberately step around the ORM and hand-write SQL
            # with an f-string. Note that the ORM equivalent of this query
            # (LegacyAccount.objects.filter(username=username, password=password))
            # would have been immune automatically - we had to work harder to
            # write the insecure version than the secure one.
            sql = (
                "SELECT id, username, password FROM forum_legacyaccount "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            executed_sql = sql  # so the page can show what really ran

            with connection.cursor() as cursor:
                # execute() with no second argument = no parameters = the
                # database receives the attacker's punctuation as SQL.
                cursor.execute(sql)
                row = cursor.fetchone()

            if row is not None:
                # The legacy table said "yes", so we log the person in as
                # whichever row came back. With ' OR '1'='1' -- that is simply
                # the first row in the table: the teacher's account.
                matched_username = row[1]
                user = User.objects.filter(username=matched_username).first()
                if user is not None:
                    # login() normally gets a user object from authenticate(),
                    # which records which backend approved them. We skipped
                    # authenticate() entirely, so we have to name the backend
                    # ourselves - a good hint that we are doing something odd.
                    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                    return redirect("home")
            error = "Invalid username or password."

        # Fall through to re-render the form with the error.
        return render(
            request,
            "forum/login.html",
            {"error": error, "executed_sql": executed_sql, "username": username},
        )

    return render(request, "forum/login.html", {})


def logout_view(request):
    logout(request)
    return redirect("home")


# ===========================================================================
# DEMO 2 - STORED (PERSISTENT) XSS IN FORUM POSTS
# ===========================================================================
#
# "Stored" means the payload is saved in the database once and then served to
# every single person who opens that thread. One malicious post by one student
# runs in the browser of the whole class, including the teacher's - with their
# session, their permissions, their view of the site.
#
# The rendering decision is made in forum/templates/forum/thread.html; look
# there for the |safe filter. This view is only responsible for saving the
# post - and for one extra sin in vulnerable mode, mark_safe() on the thread
# title.
# ===========================================================================

@login_required
def thread_detail(request, pk):
    thread = get_object_or_404(Thread.objects.select_related("course"), pk=pk)

    if request.method == "POST":
        body = request.POST.get("body", "").strip()
        if body:
            # Storing raw user input is fine and normal! The mistake is not in
            # *storing* the text, it is in *rendering* it without escaping.
            # Escaping on output (not on input) is the correct habit: the same
            # text may later be shown in HTML, in JSON, in an email...
            Post.objects.create(thread=thread, author=request.user, body=body)
        return redirect("thread_detail", pk=thread.pk)

    posts = thread.posts.select_related("author").all()

    if settings.SECURE_MODE:
        # ---------------- SECURE ----------------
        # We pass the title through as a plain string. Django's template engine
        # auto-escapes it, turning <script> into &lt;script&gt;, which the
        # browser displays as text instead of running it.
        title = thread.title
    else:
        # ---------------- VULNERABLE ----------------
        # BYPASS: mark_safe() is a promise to Django that says "trust me, this
        # string is safe HTML, do not escape it". Here we are making that
        # promise about text a student typed. Django believed us.
        title = mark_safe(thread.title)

    return render(
        request,
        "forum/thread.html",
        {"thread": thread, "posts": posts, "thread_title": title},
    )


@login_required
def course_detail(request, pk):
    course = get_object_or_404(Course, pk=pk)
    threads = course.threads.select_related("created_by").all()
    return render(request, "forum/course.html", {"course": course, "threads": threads})


# ===========================================================================
# DEMO 3 - IDOR (INSECURE DIRECT OBJECT REFERENCE) ON PRIVATE MESSAGES
# ===========================================================================
#
# The bug: the view checks that you are *logged in*, and then forgets to check
# that the message is *yours*. The id in the URL is the only thing deciding
# which message you get, and ids are just small integers you can guess.
#
# Being authenticated is not the same as being authorised. Django gives you
# @login_required out of the box, which answers "who are you?" - but only you
# can answer "are you allowed to see this particular row?".
# ===========================================================================

@login_required
def inbox(request):
    received = Message.objects.filter(recipient=request.user).select_related("sender")
    sent = Message.objects.filter(sender=request.user).select_related("recipient")
    return render(request, "forum/inbox.html", {"received": received, "sent": sent})


@login_required
def message_detail(request, pk):
    if settings.SECURE_MODE:
        # ---------------- SECURE ----------------
        # The ownership check is part of the *query*, not an afterthought.
        # If the message exists but belongs to someone else, we simply do not
        # find it - and we answer 403 instead of "not found" only when it is
        # safe to do so. (Answering 404 for someone else's message is often
        # even better: it does not confirm that the id exists at all.)
        message = Message.objects.filter(pk=pk).first()
        if message is None:
            raise PermissionDenied("No such message.")
        if request.user not in (message.recipient, message.sender):
            raise PermissionDenied("This message is not addressed to you.")
    else:
        # ---------------- VULNERABLE ----------------
        # BYPASS: @login_required above proves *who* you are. We then throw
        # that information away and fetch purely by primary key. Change the
        # number in the URL and you read somebody else's private mail.
        message = get_object_or_404(Message, pk=pk)

    return render(request, "forum/message.html", {"message": message})


# ---------------------------------------------------------------------------
# DEMO 3b - THE SAME BUG, BUT ABOUT ROLES: a teacher-only page with no check
# ---------------------------------------------------------------------------
# There is no link to this page anywhere in the student UI. That is the whole
# "defence": the URL is not advertised. Hiding a door is not locking it -
# this is sometimes called "security through obscurity", and it is not
# security. Any student who guesses /courses/1/grades/ walks straight in.
# ---------------------------------------------------------------------------

@login_required
def course_grades(request, pk):
    course = get_object_or_404(Course, pk=pk)

    if settings.SECURE_MODE:
        # ---------------- SECURE ----------------
        # Check the role *and* the relationship: you may see this page if you
        # are a teacher AND you are the teacher of this particular course.
        # (A superuser is allowed through so the admin account still works.)
        profile = getattr(request.user, "profile", None)
        is_teacher = profile is not None and profile.is_teacher
        if not (request.user.is_superuser or (is_teacher and course.teacher_id == request.user.id)):
            raise PermissionDenied("Only the teacher of this course can see the grades.")
    else:
        # ---------------- VULNERABLE ----------------
        # BYPASS: no role check at all. Django cannot guess that this page is
        # sensitive; authorisation is always the application's job. Django does
        # offer @user_passes_test / @permission_required for exactly this -
        # we just did not use them.
        pass

    grades = course.grades.select_related("student").all()
    return render(request, "forum/grades.html", {"course": course, "grades": grades})


# ===========================================================================
# DEMO 4 - CSRF ON THE "CHANGE EMAIL" FORM
# ===========================================================================
#
# CSRF = Cross-Site Request Forgery. Another site makes *your browser* send a
# request to this app. Your browser helpfully attaches your session cookie, so
# the app sees a perfectly normal, fully logged-in request from you - except
# you never clicked anything you understood.
#
# Django's defence: every POST form must carry a secret token that the
# attacker's site cannot read (the same-origin policy stops them). No token,
# no request.
#
# Note the decorator below is *always* @csrf_exempt. That is what turns off
# Django's automatic, project-wide protection. In SECURE_MODE we hand the
# request to a @csrf_protect-wrapped function to put the protection back, so
# that both versions can live in one file. In a real project you would simply
# never write @csrf_exempt in the first place.
# ===========================================================================

@csrf_exempt  # BYPASS: this single line disables Django's CSRF middleware for this view.
@login_required
def profile_view(request):
    if settings.SECURE_MODE:
        # ---------------- SECURE ----------------
        # _profile_form is wrapped in @csrf_protect below, which performs
        # exactly the check the middleware would have performed: the POST must
        # carry a valid token, and (for same-site requests) the Origin header
        # must match. Without it Django answers 403 Forbidden.
        return _profile_secure(request)

    # ---------------- VULNERABLE ----------------
    # No token is checked. Any page on the internet can POST here on behalf of
    # a logged-in student. See attacker/attacker.html.
    return _profile_form(request)


def _profile_form(request):
    """The actual form handling, shared by both modes."""
    changed = False
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        if email:
            request.user.email = email
            request.user.save(update_fields=["email"])
            changed = True
    return render(request, "forum/profile.html", {"changed": changed})


# Wrapping the shared handler puts CSRF verification back on for SECURE_MODE.
_profile_secure = csrf_protect(_profile_form)


# ===========================================================================
# DEMO 5 - SECURITY MISCONFIGURATION (DEBUG=True)
# ===========================================================================

def misconfig(request):
    """An explanation page plus a button that triggers a real 500 error."""
    return render(request, "forum/misconfig.html")


def misconfig_boom(request):
    """Deliberately crash so students can see what the error page reveals.

    With DEBUG=True (vulnerable mode) Django replies with its yellow debug
    page: the full traceback, every local variable, the list of installed
    apps, the URL configuration and a scrubbed-but-still-revealing dump of the
    settings. On a public site that is a free map of your application.

    With DEBUG=False (secure mode) the visitor gets a bare "Server Error (500)"
    and the details go to the server log where they belong.
    """
    secret_api_key = "sk-live-not-a-real-key-but-imagine-it-was"  # noqa: F841
    database_password = "hunter2"  # noqa: F841
    # Local variables like the two above are printed on Django's debug page.
    raise RuntimeError("Deliberate crash for the DEBUG=True demonstration.")


# ===========================================================================
# DEMO 6 has no view: it is about requirements.txt. See /demos and README.md.
# ===========================================================================


# ===========================================================================
# Classroom convenience: reset the database back to the seeded state
# ===========================================================================

@csrf_protect
def reset_demo(request):
    """Wipe and reseed the database so the next demo starts clean.

    Guarded three ways because a "delete everything" endpoint is itself a
    lovely vulnerability: POST only, localhost only, and CSRF-protected even
    in vulnerable mode.
    """
    if request.method != "POST":
        return redirect("demos")

    remote = request.META.get("REMOTE_ADDR", "")
    if remote not in ("127.0.0.1", "::1"):
        raise PermissionDenied("The reset button only works from localhost.")

    from django.core.management import call_command

    call_command("seed_demo", reset=True, verbosity=0)
    # Everyone is logged out, because the sessions table was wiped too.
    return HttpResponseRedirect("/demos/?reset=1")

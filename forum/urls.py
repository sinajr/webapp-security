"""URL map for the teaching lab. Every path a demo needs is listed here."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),

    # Demo 1 - SQL injection
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),

    # Demo 2 - stored XSS
    path("courses/<int:pk>/", views.course_detail, name="course_detail"),
    path("threads/<int:pk>/", views.thread_detail, name="thread_detail"),

    # Demo 3 - IDOR. Try changing the number in /messages/1/ to /messages/2/.
    path("messages/", views.inbox, name="inbox"),
    path("messages/<int:pk>/", views.message_detail, name="message_detail"),

    # Demo 3b - missing role check. Nothing links here from the student UI.
    path("courses/<int:pk>/grades/", views.course_grades, name="course_grades"),

    # Demo 4 - CSRF
    path("profile/", views.profile_view, name="profile"),

    # Demo 5 - security misconfiguration
    path("misconfig/", views.misconfig, name="misconfig"),
    path("misconfig/boom/", views.misconfig_boom, name="misconfig_boom"),

    # Explanations + classroom reset button
    path("demos/", views.demos, name="demos"),
    path("reset/", views.reset_demo, name="reset_demo"),
]

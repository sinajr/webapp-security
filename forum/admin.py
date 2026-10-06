from django.contrib import admin

from .models import Course, Grade, LegacyAccount, Message, Post, Profile, Thread

# Registered so students can poke at the data through /admin/ with the
# teacher account (prof / prof123).
admin.site.register([Profile, LegacyAccount, Course, Thread, Post, Message, Grade])

"""
Reset the lab to its starting state:  python manage.py reset_demo

This is a thin alias for `seed_demo --reset`. It wipes every table (including
sessions, so everyone is logged out) and recreates the demo users, courses,
threads, private messages and grades. Use it between classroom runs, or after
a student has pasted an XSS payload you would like to remove.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Wipe the database and recreate the demo data from scratch."

    def handle(self, *args, **options):
        call_command("migrate", verbosity=0)
        call_command("seed_demo", reset=True)

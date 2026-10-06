"""
Create the demo data:  python manage.py seed_demo

Add --reset to wipe the database first, so a class demo can be run again from
a clean slate:          python manage.py seed_demo --reset

Accounts created (all passwords are deliberately terrible - it is a lab):

    prof   / prof123    teacher, also a Django superuser (can use /admin/)
    alice  / alice123   student
    bob    / bob123     student
    carol  / carol123   student
"""

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction

from forum.models import Course, Grade, LegacyAccount, Message, Post, Profile, Thread

# (username, password, role, first name, email)
PEOPLE = [
    # The teacher is created FIRST on purpose: the SQL injection payload
    # ' OR '1'='1' --  returns the first matching row, so the attacker lands
    # in the teacher's account. That makes the demo memorable.
    ("prof", "prof123", Profile.TEACHER, "Dr. Ada Reyes", "reyes@example.edu"),
    ("alice", "alice123", Profile.STUDENT, "Alice", "alice@example.edu"),
    ("bob", "bob123", Profile.STUDENT, "Bob", "bob@example.edu"),
    ("carol", "carol123", Profile.STUDENT, "Carol", "carol@example.edu"),
]


class Command(BaseCommand):
    help = "Populate the database with the demo users, courses, threads and messages."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete all existing data first (equivalent to manage.py flush).",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            self.stdout.write("Wiping the database...")
            call_command("flush", interactive=False, verbosity=0)

        if User.objects.exists() and not options["reset"]:
            self.stdout.write(
                self.style.WARNING(
                    "Users already exist. Run with --reset to start from scratch."
                )
            )
            return

        users = {}
        for username, password, role, full_name, email in PEOPLE:
            user = User.objects.create_user(
                username=username,
                password=password,   # Django hashes this with PBKDF2 for us.
                email=email,
                first_name=full_name,
            )
            if role == Profile.TEACHER:
                user.is_staff = True
                user.is_superuser = True
                user.save()
            Profile.objects.create(user=user, role=role)

            # The "legacy" plain-text mirror of the same credentials, used
            # only by the vulnerable login path in demo 1.
            LegacyAccount.objects.create(username=username, password=password)
            users[username] = user

        prof, alice, bob, carol = (users[n] for n in ("prof", "alice", "bob", "carol"))

        # ----- Courses -------------------------------------------------
        web = Course.objects.create(
            code="CS340", title="Web Application Security", teacher=prof
        )
        web.students.set([alice, bob, carol])

        db = Course.objects.create(
            code="CS210", title="Databases", teacher=prof
        )
        db.students.set([alice, bob])

        # ----- Threads and posts ---------------------------------------
        t1 = Thread.objects.create(
            course=web, title="Welcome to CS340", created_by=prof
        )
        Post.objects.create(
            thread=t1, author=prof,
            body="Welcome everyone. Lab 1 is due next Friday. Ask questions here.",
        )
        Post.objects.create(
            thread=t1, author=alice,
            body="Is the lab done in pairs or individually?",
        )
        Post.objects.create(
            thread=t1, author=prof,
            body="Individually, but you may discuss the ideas with each other.",
        )

        t2 = Thread.objects.create(
            course=web, title="Lab 1: questions about the SQL exercise", created_by=bob
        )
        Post.objects.create(
            thread=t2, author=bob,
            body="I cannot get exercise 3 to run. Does anyone have a hint?",
        )
        Post.objects.create(
            thread=t2, author=carol,
            body="Check your quotes - mine failed because of a stray apostrophe.",
        )

        t3 = Thread.objects.create(
            course=db, title="Normalisation reading group", created_by=carol
        )
        Post.objects.create(
            thread=t3, author=carol,
            body="Meeting Tuesday at 17:00 in the library. Everyone welcome.",
        )

        # ----- Private messages (demo 3 - IDOR) ------------------------
        # Message ids 1, 2, 3... are what students will guess in the URL.
        Message.objects.create(
            sender=alice, recipient=bob,
            subject="Study group?",
            body="Want to revise for the midterm together on Sunday?",
        )
        Message.objects.create(
            sender=bob, recipient=carol,
            subject="Please do not tell anyone",
            body=(
                "I failed the retake and I am thinking about dropping the course. "
                "Please keep this between us."
            ),
        )
        Message.objects.create(
            sender=carol, recipient=bob,
            subject="Re: Please do not tell anyone",
            body="Your secret is safe with me. Talk to the professor, she is reasonable.",
        )
        Message.objects.create(
            sender=prof, recipient=alice,
            subject="Your project proposal",
            body="Nice work on the proposal. Come to office hours on Thursday.",
        )

        # ----- Grades (demo 3b - missing role check) -------------------
        for student, score, comment in [
            (alice, 92, "Excellent write-up."),
            (bob, 54, "Resit required. See me."),
            (carol, 78, "Solid work."),
        ]:
            Grade.objects.create(course=web, student=student, score=score, comment=comment)
        for student, score in [(alice, 88), (bob, 61)]:
            Grade.objects.create(course=db, student=student, score=score)

        self.stdout.write(self.style.SUCCESS("Demo data created."))
        self.stdout.write("")
        self.stdout.write("  Accounts:  prof/prof123 (teacher)   alice/alice123")
        self.stdout.write("             bob/bob123              carol/carol123")
        self.stdout.write("")
        self.stdout.write("  Start the lab with:  python manage.py runserver")

"""
Data model for a small university course forum.

Nothing here is deliberately insecure - the vulnerabilities live in the views.
The one exception is LegacyAccount, which stores plain-text passwords on
purpose so that demo 1 (SQL injection) has something juicy to leak.
"""

from django.contrib.auth.models import User
from django.db import models


class Profile(models.Model):
    """Extra information about a user: are they a student or a teacher?

    Demo 3b uses `role` for an access-control check. In the vulnerable path we
    simply forget to look at it.
    """

    STUDENT = "student"
    TEACHER = "teacher"
    ROLE_CHOICES = [(STUDENT, "Student"), (TEACHER, "Teacher")]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=STUDENT)

    @property
    def is_teacher(self):
        return self.role == self.TEACHER

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class LegacyAccount(models.Model):
    """A fake "old system we imported from" table, used only by demo 1.

    !!! Storing passwords in plain text is a serious vulnerability in itself.
    !!! Django never does this: django.contrib.auth hashes every password with
    !!! PBKDF2 and a per-user salt. This table exists so that students can see
    !!! what an attacker actually walks away with when a plain-text store is
    !!! combined with SQL injection.
    """

    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=150)  # PLAIN TEXT - demo only!

    def __str__(self):
        return self.username


class Course(models.Model):
    code = models.CharField(max_length=20, unique=True)
    title = models.CharField(max_length=200)
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name="teaching")
    students = models.ManyToManyField(User, related_name="courses", blank=True)

    def __str__(self):
        return f"{self.code} - {self.title}"


class Thread(models.Model):
    """A discussion topic inside a course."""

    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="threads")
    title = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class Post(models.Model):
    """A single message inside a thread. Demo 2 (stored XSS) lives here:
    whatever a user types into `body` is saved verbatim and shown to everyone
    else who opens the thread."""

    thread = models.ForeignKey(Thread, on_delete=models.CASCADE, related_name="posts")
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"post #{self.pk} by {self.author.username}"


class Message(models.Model):
    """A private student-to-student message. Demo 3 (IDOR) lives here."""

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    subject = models.CharField(max_length=200)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.sender} -> {self.recipient}: {self.subject}"


class Grade(models.Model):
    """A grade for one student in one course. Demo 3b (missing role check)."""

    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="grades")
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name="grades")
    score = models.IntegerField()
    comment = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["student__username"]

    def __str__(self):
        return f"{self.student.username} {self.course.code}: {self.score}"

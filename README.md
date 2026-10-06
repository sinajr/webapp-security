# Web Security Teaching Lab (Django)

A small university course forum that contains six common web vulnerabilities
**and their fixes, side by side**. It exists to be attacked in a classroom so
that students can watch each attack succeed, flip a single switch, and watch
the *same* attack fail.

The forum has students and a teacher, courses with discussion threads, a
private-message inbox, and an editable profile — an ordinary little app, with
deliberate holes in it.

---

## ⚠️ Read this first

- **This application is intentionally insecure.** That is the whole point.
- **Run it on `localhost` only.** Never deploy it, never bind it to a public
  address, never put real data in it, never expose it through a tunnel. A
  vulnerable app on the internet is somebody else's server within hours.
- **Attacking systems you do not own is a crime.** Everything in this lab is
  legal *here*, on your own machine, against an app built to be attacked.
  Doing the same to any system you have not been given **written permission**
  to test is a criminal offence in most countries (in the UK the Computer
  Misuse Act 1990, in the US the Computer Fraud and Abuse Act, and equivalents
  elsewhere). "I was only curious" is not a defence. Practise on labs that are
  meant for it: PortSwigger Web Security Academy, OWASP Juice Shop, Hack The
  Box.

---

## The one big idea

**Django is secure by default.** Read the source of each demo in
[`forum/views.py`](forum/views.py) and you will find that almost every
vulnerability required us to *switch off* a protection Django had already given
us for free. Every place we do that is marked with a comment beginning
`BYPASS:`. Finding those comments is the exercise.

The entire lab is controlled by one environment variable, `SECURE_MODE`:

| `SECURE_MODE` | What runs | Banner |
|---|---|---|
| `0` (default) | the vulnerable code paths | red |
| `1` | the fixed code paths | green |

Each demo view branches on `settings.SECURE_MODE` with a plain `if/else`, so
the vulnerable and secure versions sit next to each other in one file and you
can diff them by eye.

---

## Setup

Requires Python 3.10+ (developed on 3.14).

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the database and the demo data (users, courses, messages, grades)
python manage.py migrate
python manage.py seed_demo

# 4. Run it (vulnerable mode — note the red banner)
python manage.py runserver
```

Then open <http://127.0.0.1:8000/>. Start at the **Demos** page
(<http://127.0.0.1:8000/demos/>), which explains every attack with exact,
copy-pasteable steps.

### Demo accounts

| Username | Password | Role |
|---|---|---|
| `prof` | `prof123` | teacher (also a Django admin — `/admin/`) |
| `alice` | `alice123` | student |
| `bob` | `bob123` | student |
| `carol` | `carol123` | student |

(These passwords are deliberately terrible. It is a lab.)

---

## Switching modes

Mode is chosen at server start from the environment. Stop the server
(`Ctrl+C`) and start it again with the switch flipped:

```bash
# Vulnerable (the default)
python manage.py runserver

# Secure
SECURE_MODE=1 python manage.py runserver
```

On Windows PowerShell:

```powershell
$env:SECURE_MODE=1; python manage.py runserver
```

Nothing else changes between the two runs — only which side of each `if`
statement executes. The banner across the top of every page tells you which
mode you are in (red = vulnerable, green = secure).

---

## The six demos at a glance

Full instructions live on the in-app **/demos/** page. Short version:

1. **SQL injection** on the login form. Log in as the teacher with username
   `' OR '1'='1' --` and no real password. *Vulnerable:* hand-built SQL via
   `connection.cursor()`. *Fix:* the ORM + `authenticate()`.
2. **Stored XSS** in forum posts. Post `<script>…</script>`; it runs in every
   classmate's browser. *Vulnerable:* the `|safe` filter. *Fix:* default
   auto-escaping, `HttpOnly`/`SameSite` cookies, and a Content-Security-Policy
   header.
3. **IDOR** on `/messages/<id>/`. Change the number in the URL to read another
   student's private mail. *Fix:* filter by the logged-in user, else 403.
   Variant **3b:** a teacher-only `/courses/<id>/grades/` page with no role
   check that any student can reach by guessing the URL.
4. **CSRF** on the change-email form. A page served from another origin
   (`attacker/attacker.html`) silently changes your email while you are logged
   in. *Vulnerable:* `@csrf_exempt`. *Fix:* remove it; the `{% csrf_token %}`
   in the template is then actually checked.
5. **Security misconfiguration.** With `DEBUG=True`, `/misconfig/boom/` shows
   an error page that leaks local variables, settings and installed apps.
   *Fix:* `DEBUG=False`. Learn the checklist with
   `python manage.py check --deploy`.
6. **Vulnerable dependency.** `requirements.txt` pins an old `PyYAML` with a
   real CVE so a scanner reports it: `pip install pip-audit` then
   `pip-audit -r requirements.txt`.

---

## Resetting between classes

A demo run fills the forum with XSS payloads and changed emails. To wipe
everything and recreate the seeded state:

```bash
python manage.py reset_demo
```

There is also a **Reset the demo database** button at the bottom of the
**/demos/** page (POST-only, localhost-only, CSRF-protected even in vulnerable
mode). Both log everyone out, because the sessions table is wiped too.

---

## A 15-minute live classroom walkthrough

Have two terminals open. Terminal A runs the Django app; terminal B is for the
attacker page and the dependency scan. Start in **vulnerable mode**.

> Before you start: `python manage.py reset_demo`, then
> `python manage.py runserver` in terminal A. Point out the **red banner** and
> say what it means.

1. **SQL injection (2 min).** Go to `/login/`, logged out. Enter username
   `' OR '1'='1' --`, password `x`. You are now the teacher. Scroll down — the
   page prints the exact SQL that ran; show the apostrophe splitting the query.
   *Say:* "The database could not tell my punctuation from the programmer's
   query."

2. **Stored XSS (3 min).** As `bob`, open the *Welcome to CS340* thread and
   post `<script>alert('owned ' + document.cookie)</script>`. It fires. Now log
   out, log in as `alice`, open the same thread — **it fires for her too.**
   *Say:* "One post, saved once, runs in the whole class's browser — including
   the session cookie, which is all I need to become them."

3. **IDOR (2 min).** As `alice`, open `/messages/`, then hand-edit the URL to
   `/messages/2/`. Read Bob and Carol's private conversation. Then visit
   `/courses/1/grades/` — a page no student is ever linked to — and show the
   whole class's grades. *Say:* "Being logged in is not the same as being
   allowed."

4. **CSRF (3 min).** As `carol`, show the current email on `/profile/`. In
   terminal B: `cd attacker && python -m http.server 9000`. In the browser open
   `http://127.0.0.1:9000/attacker.html` (a fake "free exam papers" page).
   Return to `/profile/`, reload — the email is now `attacker@evil.example`.
   *Say:* "She clicked nothing on our site. Her browser attached her cookie
   automatically."

5. **Misconfiguration (2 min).** Open `/misconfig/` and click *Trigger an
   unhandled error*. Scroll to "Local vars" to reveal `secret_api_key` and
   `database_password`; scroll on to the settings dump. *Say:* "On a public
   server, anyone who can crash a page gets this."

6. **Vulnerable dependency (1 min).** In terminal B: `pip install pip-audit`
   then `pip-audit -r requirements.txt`. Read out the CVE and its fix version.
   *Say:* "This bug isn't in our code, and we'd never find it by reading our
   code."

7. **Flip the switch (2 min).** Stop terminal A, restart with
   `SECURE_MODE=1 python manage.py runserver`. Point out the **green banner**.
   Now repeat, fast: the SQLi login is rejected; the XSS payload shows as
   text (open the dev console to see the CSP block it); `/messages/2/` and
   `/courses/1/grades/` return **403**; the attacker page's POST returns
   **403**; the crash page shows a bare "Server Error (500)" with no secrets.
   *Close with:* `python manage.py check --deploy` — the tool that finds
   misconfigurations for you.

**One-line takeaway for the board:** *You rarely have to add security to a
Django app. It is already there. The job is to not switch it off.*

---

## Project layout

```
config/            Django project: settings, URLs, the CSP middleware
forum/             the one app
  models.py        users, courses, threads, posts, messages, grades
  views.py         EVERY demo lives here, each as an if SECURE_MODE / else
  urls.py          the routes each demo needs
  templates/forum/ pages (thread.html holds the |safe XSS decision)
  static/forum/    stylesheet
  management/commands/
    seed_demo.py   create the demo data  (--reset to wipe first)
    reset_demo.py  wipe and recreate     (alias for seed_demo --reset)
attacker/
  attacker.html    the cross-origin page for the CSRF demo (serve on :9000)
requirements.txt   Django + one deliberately vulnerable pin (demo 6)
```

Written to be read by second-year students: short files, heavy comments, no
build step, no JavaScript framework, no third-party packages beyond Django.

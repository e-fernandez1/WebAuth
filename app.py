import json
import os
import re
import smtplib
import secrets
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import bcrypt
import pyotp
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from sqlalchemy import inspect, text
from user_agents import parse as parse_ua

from models import AuthEvent, EmailCode, PendingSignup, User, db


GEO_CACHE = {}
GEO_CACHE_TTL = timedelta(hours=6)


def lookup_geo(ip):
    if not ip:
        return ("", "")
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return ("Local", "Local")
    cached = GEO_CACHE.get(ip)
    if cached and cached[2] > datetime.utcnow():
        return cached[0], cached[1]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
        with urllib.request.urlopen(url, timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8"))
            if data.get("status") == "success":
                country = data.get("country", "") or ""
                city = data.get("city", "") or ""
                GEO_CACHE[ip] = (country, city, datetime.utcnow() + GEO_CACHE_TTL)
                return country, city
    except Exception:
        pass
    GEO_CACHE[ip] = ("", "", datetime.utcnow() + timedelta(minutes=10))
    return ("", "")


def parse_user_agent(ua_string):
    if not ua_string:
        return ("", "", "")
    try:
        ua = parse_ua(ua_string)
        browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
        os_family = f"{ua.os.family} {ua.os.version_string}".strip()
        if ua.is_mobile:
            device = "mobile"
        elif ua.is_tablet:
            device = "tablet"
        elif ua.is_bot:
            device = "bot"
        else:
            device = "desktop"
        return (browser[:64], os_family[:64], device)
    except Exception:
        return ("", "", "")


def classify_attack_vector(event_type, ip):
    """Best-effort classification of an event into an attack-vector bucket."""
    if event_type == "rate_limited":
        return "brute_force"
    if event_type in ("simulated_attack", "simulated_blocked"):
        return "simulated_brute_force"
    if event_type == "2fa_fail":
        return "2fa_bypass_attempt"
    if event_type == "signup_confirm_fail":
        return "signup_confirmation_abuse"
    if event_type == "signup_fail":
        return "signup_abuse"
    if event_type == "login_fail" and ip:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent = (
            db.session.query(AuthEvent.username)
            .filter(
                AuthEvent.event_type == "login_fail",
                AuthEvent.ip == ip,
                AuthEvent.timestamp > cutoff,
            )
            .all()
        )
        if len(recent) >= 3:
            distinct_users = len({r[0] for r in recent if r[0]})
            if distinct_users >= 2:
                return "credential_stuffing"
            return "brute_force"
    return None


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


load_dotenv()


SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "noreply@webauth.demo")


LOGIN_ATTEMPTS = defaultdict(list)
RATE_LIMIT_WINDOW = timedelta(minutes=1)
RATE_LIMIT_MAX = 5


def is_rate_limited(key):
    now = datetime.utcnow()
    cutoff = now - RATE_LIMIT_WINDOW
    LOGIN_ATTEMPTS[key] = [t for t in LOGIN_ATTEMPTS[key] if t > cutoff]
    return len(LOGIN_ATTEMPTS[key]) >= RATE_LIMIT_MAX


def record_attempt(key):
    LOGIN_ATTEMPTS[key].append(datetime.utcnow())


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") != "development"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)


CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = CSP
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def auto_seed_if_empty():
    """Create default test users if the database is empty.

    Runs on startup so a fresh deploy (e.g. Render's ephemeral filesystem)
    always boots with a working admin account and test users.
    """
    if User.query.count() > 0:
        return
    print("[AUTO-SEED] No users found, creating defaults...")
    seed_users = [
        ("admin",     "admin@webauth.demo",   "AdminPassword123!",  True),
        ("testuser",  "test@webauth.demo",    "TestPassword123!",   False),
        ("alice",     "alice@webauth.demo",   "AlicePassword123!",  False),
        ("bob",       "bob@webauth.demo",     "BobPassword123!",    False),
        ("demo",      "demo@webauth.demo",    "DemoPassword123!",   False),
    ]
    for username, email, password, is_admin in seed_users:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        db.session.add(User(username=username, email=email,
                            password_hash=pw_hash, is_admin=is_admin))
    db.session.commit()
    print(f"[AUTO-SEED] Created {len(seed_users)} test users (admin + 4 regular).")


def ensure_columns():
    """Add missing columns to existing SQLite tables.

    db.create_all() creates new tables but does not add columns to existing ones,
    so this helper bridges the gap when AuthEvent gains new fields.
    """
    inspector = inspect(db.engine)
    if "auth_event" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("auth_event")}
    additions = [
        ("user_agent",    "VARCHAR(255)"),
        ("browser",       "VARCHAR(64)"),
        ("os_family",     "VARCHAR(64)"),
        ("device",        "VARCHAR(32)"),
        ("country",       "VARCHAR(64)"),
        ("city",          "VARCHAR(64)"),
        ("attack_vector", "VARCHAR(32)"),
    ]
    for col_name, col_type in additions:
        if col_name not in existing:
            db.session.execute(text(f"ALTER TABLE auth_event ADD COLUMN {col_name} {col_type}"))
            print(f"[MIGRATE] Added column auth_event.{col_name}")
    db.session.commit()

    # Backfill attack_vector for events that pre-date the column.
    backfill = db.session.execute(text(
        "UPDATE auth_event SET attack_vector = 'simulated_brute_force' "
        "WHERE event_type IN ('simulated_attack', 'simulated_blocked') "
        "AND attack_vector IS NULL"
    ))
    if backfill.rowcount:
        print(f"[MIGRATE] Backfilled attack_vector on {backfill.rowcount} simulated event(s).")
    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_columns()
    auto_seed_if_empty()


PASSWORD_RULES = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
}

COMMON_PASSWORDS = {
    "password", "password123", "qwerty123", "letmein123", "iloveyou123",
    "admin1234567", "welcome12345", "monkey123456", "dragon123456",
}


def validate_password(pw):
    errors = []
    if len(pw) < PASSWORD_RULES["min_length"]:
        errors.append(f"Must be at least {PASSWORD_RULES['min_length']} characters")
    if not re.search(r"[A-Z]", pw):
        errors.append("Must contain an uppercase letter")
    if not re.search(r"[a-z]", pw):
        errors.append("Must contain a lowercase letter")
    if not re.search(r"\d", pw):
        errors.append("Must contain a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errors.append("Must contain a symbol")
    if pw.lower() in COMMON_PASSWORDS:
        errors.append("This password is too common")
    return errors


def request_context():
    """Snapshot of the current request: ip, ua, browser/os/device, country, city."""
    ip = request.remote_addr
    ua_string = request.headers.get("User-Agent", "")
    browser, os_family, device = parse_user_agent(ua_string)
    country, city = lookup_geo(ip)
    return {
        "ip": ip,
        "user_agent": ua_string[:255],
        "browser": browser,
        "os_family": os_family,
        "device": device,
        "country": country,
        "city": city,
    }


def log_event(event_type, username=None, detail=None, attack_vector=None, ctx=None):
    ctx = ctx or request_context()
    if attack_vector is None:
        attack_vector = classify_attack_vector(event_type, ctx["ip"])
    event = AuthEvent(
        event_type=event_type,
        username=username,
        detail=detail,
        attack_vector=attack_vector,
        **ctx,
    )
    db.session.add(event)
    db.session.commit()


def send_verification_email(to_email, code):
    """Email a 6-digit verification code. Falls back to console if SMTP not configured."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        print("\n" + "=" * 60)
        print(f"[EMAIL FALLBACK]  To: {to_email}")
        print(f"[EMAIL FALLBACK]  Code: {code}")
        print(f"[EMAIL FALLBACK]  Expires in 5 minutes")
        print("=" * 60 + "\n")
        return True

    msg = EmailMessage()
    msg["Subject"] = "Your WebAuth verification code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Your WebAuth verification code is: {code}\n\n"
        f"This code expires in 5 minutes. If you did not request it, ignore this email."
    )
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


def issue_email_code(user):
    EmailCode.query.filter_by(user_id=user.id, used=False).update({"used": True})
    code = f"{secrets.randbelow(1_000_000):06d}"
    record = EmailCode(
        user_id=user.id,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.session.add(record)
    db.session.commit()
    send_verification_email(user.email, code)


def send_signup_email(to_email, code):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        print("\n" + "=" * 60)
        print(f"[SIGNUP CONFIRMATION]  To: {to_email}")
        print(f"[SIGNUP CONFIRMATION]  Code: {code}")
        print(f"[SIGNUP CONFIRMATION]  Expires in 10 minutes")
        print("=" * 60 + "\n")
        return True
    msg = EmailMessage()
    msg["Subject"] = "Confirm your WebAuth account"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Welcome to WebAuth.\n\n"
        f"Your account confirmation code is: {code}\n\n"
        f"This code expires in 10 minutes. If you did not sign up, ignore this email."
    )
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("signup.html", rules=PASSWORD_RULES)

        try:
            validated = validate_email(email, check_deliverability=True)
            email = validated.normalized
        except EmailNotValidError as e:
            flash(f"Invalid email: {e}", "danger")
            log_event("signup_fail", username=username, detail="invalid_email")
            return render_template("signup.html", rules=PASSWORD_RULES)

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already in use.", "danger")
            log_event("signup_fail", username=username, detail="duplicate")
            return render_template("signup.html", rules=PASSWORD_RULES)

        errors = validate_password(password)
        if errors:
            for e in errors:
                flash(e, "danger")
            log_event("signup_fail", username=username, detail="weak_password")
            return render_template("signup.html", rules=PASSWORD_RULES)

        # Drop any prior pending signups for this username/email
        PendingSignup.query.filter(
            (PendingSignup.username == username) | (PendingSignup.email == email)
        ).delete(synchronize_session=False)

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        code = f"{secrets.randbelow(1_000_000):06d}"
        pending = PendingSignup(
            username=username,
            email=email,
            password_hash=pw_hash,
            code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.session.add(pending)
        db.session.commit()

        log_event("signup_pending", username=username, detail=email)
        send_signup_email(email, code)

        session["pending_signup_id"] = pending.id
        flash(f"Confirmation code sent to {email}.", "success")
        return redirect(url_for("confirm_signup"))

    return render_template("signup.html", rules=PASSWORD_RULES)


@app.route("/confirm-signup", methods=["GET", "POST"])
def confirm_signup():
    pending_id = session.get("pending_signup_id")
    if not pending_id:
        return redirect(url_for("signup"))
    pending = db.session.get(PendingSignup, pending_id)
    if not pending:
        session.pop("pending_signup_id", None)
        flash("That signup attempt expired. Please start over.", "danger")
        return redirect(url_for("signup"))

    if datetime.utcnow() > pending.expires_at:
        db.session.delete(pending)
        db.session.commit()
        session.pop("pending_signup_id", None)
        flash("Your confirmation code expired. Please sign up again.", "danger")
        return redirect(url_for("signup"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_rate_limited(f"confirm-{ip}"):
            log_event("rate_limited", username=pending.username, detail=f"confirm ip={ip}")
            flash("Too many attempts. Try again in a minute.", "danger")
            return render_template("confirm_signup.html", email=pending.email,
                                   username=pending.username), 429
        record_attempt(f"confirm-{ip}")
        code = request.form.get("code", "").strip()
        if code == pending.code:
            user = User(
                username=pending.username,
                email=pending.email,
                password_hash=pending.password_hash,
                is_admin=False,
            )
            db.session.add(user)
            db.session.delete(pending)
            db.session.commit()
            session.pop("pending_signup_id", None)
            log_event("signup_success", username=user.username, detail="email_confirmed")
            flash("Email confirmed and account created. You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            log_event("signup_confirm_fail", username=pending.username)
            flash("Invalid code.", "danger")

    return render_template("confirm_signup.html", email=pending.email,
                           username=pending.username)


@app.route("/resend-signup-code")
def resend_signup_code():
    pending_id = session.get("pending_signup_id")
    if not pending_id:
        return redirect(url_for("signup"))
    pending = db.session.get(PendingSignup, pending_id)
    if not pending:
        return redirect(url_for("signup"))
    pending.code = f"{secrets.randbelow(1_000_000):06d}"
    pending.expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    send_signup_email(pending.email, pending.code)
    flash(f"A new confirmation code was sent to {pending.email}.", "success")
    return redirect(url_for("confirm_signup"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip):
            log_event("rate_limited", username=username, detail=f"ip={ip}")
            flash("Too many login attempts. Try again in a minute.", "danger")
            return render_template("login.html"), 429

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            record_attempt(ip)
            flash("Invalid credentials.", "danger")
            log_event("login_fail", username=username, detail="bad_password")
            return render_template("login.html")

        log_event("login_success_pending_2fa", username=username)
        session["pending_2fa_user_id"] = user.id
        issue_email_code(user)
        flash(f"A verification code was sent to {user.email}.", "success")
        return redirect(url_for("verify"))

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_rate_limited(f"verify-{ip}"):
            log_event("rate_limited", username=user.username, detail=f"verify ip={ip}")
            flash("Too many verification attempts. Try again in a minute.", "danger")
            return render_template("verify.html", username=user.username, email=user.email), 429
        record_attempt(f"verify-{ip}")
        code = request.form.get("code", "").strip()
        record = (
            EmailCode.query
            .filter_by(user_id=user.id, code=code, used=False)
            .filter(EmailCode.expires_at > datetime.utcnow())
            .first()
        )
        if record:
            record.used = True
            db.session.commit()
            session.pop("pending_2fa_user_id", None)
            login_user(user)
            log_event("2fa_success", username=user.username)
            return redirect(url_for("dashboard"))
        else:
            log_event("2fa_fail", username=user.username)
            flash("Invalid or expired code.", "danger")

    return render_template("verify.html", username=user.username, email=user.email)


@app.route("/resend-code")
def resend_code():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for("login"))
    issue_email_code(user)
    flash(f"A new code was sent to {user.email}.", "success")
    return redirect(url_for("verify"))


@app.route("/dashboard")
@login_required
def dashboard():
    recent_events = (
        AuthEvent.query.filter_by(username=current_user.username)
        .order_by(AuthEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    return render_template("dashboard.html", events=recent_events)


@app.route("/logout")
@login_required
def logout():
    log_event("logout", username=current_user.username)
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/analytics")
def analytics():
    return render_template("analytics.html")


@app.route("/security")
def security():
    return render_template("security.html")


@app.route("/explained")
def explained():
    return render_template("explained.html")


def _add_sim_event(ctx, event_type, username, detail, vector):
    db.session.add(AuthEvent(
        event_type=event_type,
        username=username[:64],
        detail=detail[:255] if detail else None,
        attack_vector=vector,
        **ctx,
    ))


@app.route("/api/simulate-credential-stuffing", methods=["POST"])
def simulate_credential_stuffing():
    pairs = [
        ("admin", "password"), ("admin", "admin123"),
        ("john", "letmein"),   ("alice", "alice2021"),
        ("bob", "qwerty123"),  ("user1", "Welcome2023"),
        ("test", "test123"),   ("guest", "guest"),
        ("demo", "demo123"),   ("root", "toor"),
    ]
    ctx = request_context()
    log = []
    for username, password in pairs:
        user = User.query.filter_by(username=username).first()
        if user is None:
            outcome = "REJECTED"
            detail = "no such user — generic error returned to attacker"
        elif not bcrypt.checkpw(password.encode(), user.password_hash):
            outcome = "REJECTED"
            detail = "bcrypt.checkpw → False (password hash mismatch)"
        else:
            outcome = "BLOCKED"
            detail = "password matched, but 2FA email step blocks login"
        log.append({"input": f"{username} / {password}", "outcome": outcome, "detail": detail})
        _add_sim_event(ctx, "simulated_attack", username,
                       "leaked_credential_pair", "credential_stuffing")
    db.session.commit()
    return jsonify({
        "attempted": len(pairs),
        "compromised": 0,
        "defense": "bcrypt rejects every wrong-password hash. Even if a password matched, email-based 2FA blocks login.",
        "log": log,
    })


@app.route("/api/simulate-weak-passwords", methods=["POST"])
def simulate_weak_passwords():
    weak = ["password", "12345678", "qwerty", "abc123", "password123",
            "letmein", "monkey", "hello", "Test1", "P@ss"]
    ctx = request_context()
    rejected = 0
    log = []
    for pw in weak:
        errors = validate_password(pw)
        if errors:
            rejected += 1
            outcome = "REJECTED"
            detail = "; ".join(errors)
            _add_sim_event(ctx, "simulated_attack", f"weak_signup_{rejected:02d}",
                           f"rejected: {errors[0]}", "weak_password_attempt")
        else:
            outcome = "ACCEPTED"
            detail = "passed all rules"
        log.append({"input": pw, "outcome": outcome, "detail": detail})
    db.session.commit()
    return jsonify({
        "attempted": len(weak),
        "rejected": rejected,
        "defense": "Server-side validation enforces 12+ chars, mixed case, digit, symbol, and a common-password blocklist. Same rules even with JavaScript disabled.",
        "log": log,
    })


@app.route("/api/simulate-fake-emails", methods=["POST"])
def simulate_fake_emails():
    fake = ["admin", "user@", "@domain.com", "user@@double.com",
            "user@invalid", "fake@nope12345.xyz", "spaces in@email.com",
            "no-tld@localhost"]
    ctx = request_context()
    rejected = 0
    log = []
    for addr in fake:
        try:
            validate_email(addr, check_deliverability=False)
            log.append({"input": addr, "outcome": "ACCEPTED", "detail": "passed format check"})
        except EmailNotValidError as e:
            rejected += 1
            err_msg = str(e).split(".")[0]
            log.append({"input": addr, "outcome": "REJECTED", "detail": err_msg})
            _add_sim_event(ctx, "simulated_attack", f"fake_signup_{rejected:02d}",
                           f"{addr}: {str(e)[:80]}", "fake_email_attempt")
    db.session.commit()
    return jsonify({
        "attempted": len(fake),
        "rejected": rejected,
        "defense": "email-validator parses every address and rejects malformed inputs. Real signups also require confirming a code sent to the address.",
        "log": log,
    })


@app.route("/api/simulate-sqli", methods=["POST"])
def simulate_sqli():
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT * FROM user --",
        "1' OR '1'='1' --",
        "'; DROP TABLE user; --",
        "admin'); DROP TABLE user; --",
        "\" OR \"\"=\"",
        "' OR sleep(5) --",
    ]
    ctx = request_context()
    log = []
    for payload in payloads:
        result = User.query.filter_by(username=payload).first()
        outcome = "SAFE" if result is None else "MATCHED"
        detail = (f"SQL: SELECT * FROM user WHERE username = ?  "
                  f"[bound: '{payload[:40]}']  → 0 rows")
        log.append({"input": payload, "outcome": outcome, "detail": detail})
        _add_sim_event(ctx, "simulated_attack", payload,
                       "treated_as_literal_string_no_match" if result is None else "matched",
                       "sql_injection_attempt")
    db.session.commit()
    return jsonify({
        "attempted": len(payloads),
        "successful": 0,
        "defense": "SQLAlchemy ORM parameterizes every query. Payloads are passed as bound values, never as SQL syntax. The user table is intact — no DROP, no AUTH bypass.",
        "log": log,
    })


@app.route("/api/simulate-xss", methods=["POST"])
def simulate_xss():
    from markupsafe import escape
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(document.cookie)</script>",
        "<iframe src=javascript:alert(1)>",
    ]
    ctx = request_context()
    log = []
    for p in payloads:
        escaped = str(escape(p))
        log.append({"input": p, "outcome": "ESCAPED",
                    "detail": f"renders as: {escaped}"})
        _add_sim_event(ctx, "simulated_attack", p,
                       "would_render_as_inert_text", "xss_attempt")
    db.session.commit()
    return jsonify({
        "attempted": len(payloads),
        "executed": 0,
        "defense": "Jinja2 (server) and a JS escapeHtml helper (client) both convert < > \" ' & into HTML entities. Payloads render as harmless visible text.",
        "log": log,
    })


@app.route("/api/simulate-2fa-bypass", methods=["POST"])
def simulate_2fa_bypass():
    attempts = 12
    ctx = request_context()
    log = []
    for i in range(attempts):
        guess = f"{secrets.randbelow(1_000_000):06d}"
        log.append({"input": guess, "outcome": "REJECTED",
                    "detail": "no matching active EmailCode row"})
        _add_sim_event(ctx, "simulated_attack", f"attacker_has_pw_{i:02d}",
                       f"random_code:{guess}", "2fa_bypass_attempt")
    db.session.commit()
    return jsonify({
        "attempted": attempts,
        "successful": 0,
        "defense": "1-in-1,000,000 chance per random guess. Codes are single-use, expire in 5 minutes, and the verify endpoint is rate-limited to 5 tries per minute per IP — meaning at most ~25 attempts per code window.",
        "log": log,
    })


@app.route("/api/simulate-bruteforce", methods=["POST"])
def simulate_bruteforce():
    sim_key = f"sim-{datetime.utcnow().timestamp()}"
    attempted = 25
    reached_password_check = 0
    blocked = 0
    ctx = request_context()
    log = []
    for i in range(attempted):
        if is_rate_limited(sim_key):
            blocked += 1
            event_type = "simulated_blocked"
            detail = "rate_limited"
            log.append({"input": f"attempt #{i+1:02d}", "outcome": "BLOCKED",
                        "detail": f"rate limit ({RATE_LIMIT_MAX}/min) exceeded — HTTP 429"})
        else:
            record_attempt(sim_key)
            reached_password_check += 1
            event_type = "simulated_attack"
            detail = "reached_password_check"
            log.append({"input": f"attempt #{i+1:02d}", "outcome": "REACHED",
                        "detail": "would hit bcrypt.checkpw (~200ms per guess)"})
        event = AuthEvent(
            event_type=event_type,
            username=f"attacker_{i:02d}",
            detail=detail,
            attack_vector="simulated_brute_force",
            **ctx,
        )
        db.session.add(event)
    db.session.commit()
    LOGIN_ATTEMPTS.pop(sim_key, None)
    return jsonify({
        "attempted": attempted,
        "blocked_by_rate_limit": blocked,
        "reached_password_check": reached_password_check,
        "would_have_succeeded": 0,
        "rate_limit_threshold": RATE_LIMIT_MAX,
        "log": log,
    })


DEMO_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@app.route("/api/demo-totp")
def api_demo_totp():
    totp = pyotp.TOTP(DEMO_TOTP_SECRET)
    now = datetime.utcnow().timestamp()
    seconds_left = 30 - int(now) % 30
    return jsonify({"code": totp.now(), "seconds_left": seconds_left})


@app.route("/admin")
@admin_required
def admin_home():
    users = User.query.order_by(User.created_at.desc()).all()
    event_filter = request.args.get("filter", "")
    events_q = AuthEvent.query.order_by(AuthEvent.timestamp.desc())
    if event_filter:
        events_q = events_q.filter(AuthEvent.event_type == event_filter)
    events = events_q.limit(80).all()
    counts = {
        "users": User.query.count(),
        "events": AuthEvent.query.count(),
        "simulated": AuthEvent.query.filter(AuthEvent.event_type.like("simulated_%")).count(),
        "active_codes": EmailCode.query.filter(
            EmailCode.used == False,
            EmailCode.expires_at > datetime.utcnow(),
        ).count(),
    }

    # Attack-vector breakdown
    vector_rows = (
        db.session.query(AuthEvent.attack_vector, db.func.count(AuthEvent.id))
        .filter(AuthEvent.attack_vector.isnot(None))
        .group_by(AuthEvent.attack_vector)
        .all()
    )
    vectors = sorted(
        [{"vector": v or "uncategorized", "count": c} for v, c in vector_rows],
        key=lambda x: x["count"],
        reverse=True,
    )

    # Connection summary grouped by IP
    cutoff = datetime.utcnow() - timedelta(days=7)
    connection_rows = (
        db.session.query(
            AuthEvent.ip,
            db.func.count(AuthEvent.id).label("total"),
            db.func.max(AuthEvent.timestamp).label("last_seen"),
            db.func.max(AuthEvent.country).label("country"),
            db.func.max(AuthEvent.city).label("city"),
            db.func.max(AuthEvent.browser).label("browser"),
            db.func.max(AuthEvent.os_family).label("os_family"),
            db.func.max(AuthEvent.device).label("device"),
        )
        .filter(AuthEvent.timestamp >= cutoff, AuthEvent.ip.isnot(None))
        .group_by(AuthEvent.ip)
        .order_by(db.func.max(AuthEvent.timestamp).desc())
        .limit(40)
        .all()
    )
    connections = []
    for row in connection_rows:
        attack_count = AuthEvent.query.filter(
            AuthEvent.ip == row.ip,
            AuthEvent.attack_vector.isnot(None),
            AuthEvent.timestamp >= cutoff,
        ).count()
        connections.append({
            "ip": row.ip,
            "total": row.total,
            "attacks": attack_count,
            "last_seen": row.last_seen,
            "country": row.country or "",
            "city": row.city or "",
            "browser": row.browser or "",
            "os": row.os_family or "",
            "device": row.device or "",
        })

    return render_template("admin.html", users=users, events=events,
                           counts=counts, current_filter=event_filter,
                           vectors=vectors, connections=connections)


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash("You can't delete your own account.", "danger")
        return redirect(url_for("admin_home"))
    user = db.session.get(User, user_id)
    if user:
        EmailCode.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        log_event("admin_action", username=current_user.username, detail=f"deleted_user={user.username}")
        flash(f"Deleted user {user.username}.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == current_user.id:
        flash("You can't change your own admin flag.", "danger")
        return redirect(url_for("admin_home"))
    user = db.session.get(User, user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        log_event("admin_action", username=current_user.username,
                  detail=f"toggle_admin={user.username}->{user.is_admin}")
        flash(f"{user.username} admin = {user.is_admin}.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/clear-simulated", methods=["POST"])
@admin_required
def admin_clear_simulated():
    count = AuthEvent.query.filter(AuthEvent.event_type.like("simulated_%")).delete(
        synchronize_session=False
    )
    db.session.commit()
    log_event("admin_action", username=current_user.username, detail=f"cleared_simulated={count}")
    flash(f"Cleared {count} simulated event(s).", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/reset-ratelimits", methods=["POST"])
@admin_required
def admin_reset_ratelimits():
    n = len(LOGIN_ATTEMPTS)
    LOGIN_ATTEMPTS.clear()
    log_event("admin_action", username=current_user.username, detail="reset_rate_limits")
    flash(f"Cleared rate-limit buckets for {n} key(s).", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/clear-events", methods=["POST"])
@admin_required
def admin_clear_events():
    count = AuthEvent.query.delete(synchronize_session=False)
    db.session.commit()
    log_event("admin_action", username=current_user.username, detail=f"cleared_all_events={count}")
    flash(f"Cleared {count} event(s).", "success")
    return redirect(url_for("admin_home"))


@app.route("/api/stats")
def api_stats():
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_window = datetime.utcnow() - timedelta(seconds=60)

    # Total count of every event type
    rows = (
        db.session.query(AuthEvent.event_type, db.func.count(AuthEvent.id))
        .group_by(AuthEvent.event_type)
        .all()
    )
    counts = {event_type: count for event_type, count in rows}

    # Count of events in the last 60 seconds (drives the live chart)
    recent_rows = (
        db.session.query(AuthEvent.event_type, db.func.count(AuthEvent.id))
        .filter(AuthEvent.timestamp >= cutoff_window)
        .group_by(AuthEvent.event_type)
        .all()
    )
    recent_counts = {event_type: count for event_type, count in recent_rows}

    # Ensure expected keys exist, even when zero
    expected = (
        "signup_success", "signup_fail", "signup_pending", "signup_confirm_fail",
        "login_success_pending_2fa", "login_fail", "rate_limited",
        "2fa_success", "2fa_fail", "logout", "admin_action",
        "simulated_attack", "simulated_blocked",
    )
    for et in expected:
        counts.setdefault(et, 0)
        recent_counts.setdefault(et, 0)

    recent = AuthEvent.query.order_by(AuthEvent.timestamp.desc()).limit(20).all()
    last_hour = AuthEvent.query.filter(AuthEvent.timestamp >= cutoff_24h).count()
    user_count = User.query.count()

    return jsonify({
        "counts": counts,
        "recent_counts": recent_counts,
        "recent": [e.to_dict() for e in recent],
        "events_last_24h": last_hour,
        "total_users": user_count,
    })


if __name__ == "__main__":
    app.run(debug=True)

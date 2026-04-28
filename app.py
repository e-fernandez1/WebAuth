import os
import re
import smtplib
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import bcrypt
import pyotp
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from models import AuthEvent, EmailCode, User, db


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
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "noreply@securauth.demo")


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
        ("admin",     "admin@securauth.demo",   "AdminPassword123!",  True),
        ("testuser",  "test@securauth.demo",    "TestPassword123!",   False),
        ("alice",     "alice@securauth.demo",   "AlicePassword123!",  False),
        ("bob",       "bob@securauth.demo",     "BobPassword123!",    False),
        ("demo",      "demo@securauth.demo",    "DemoPassword123!",   False),
    ]
    for username, email, password, is_admin in seed_users:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        db.session.add(User(username=username, email=email,
                            password_hash=pw_hash, is_admin=is_admin))
    db.session.commit()
    print(f"[AUTO-SEED] Created {len(seed_users)} test users (admin + 4 regular).")


with app.app_context():
    db.create_all()
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


def log_event(event_type, username=None, detail=None):
    event = AuthEvent(
        event_type=event_type,
        username=username,
        detail=detail,
        ip=request.remote_addr,
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
    msg["Subject"] = "Your SecureAuth verification code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Your SecureAuth verification code is: {code}\n\n"
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

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        user = User(username=username, email=email, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()

        log_event("signup_success", username=username)
        flash("Account created. Log in below — we'll email you a verification code.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", rules=PASSWORD_RULES)


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


@app.route("/api/simulate-bruteforce", methods=["POST"])
def simulate_bruteforce():
    sim_key = f"sim-{datetime.utcnow().timestamp()}"
    attempted = 25
    reached_password_check = 0
    blocked = 0
    for i in range(attempted):
        if is_rate_limited(sim_key):
            blocked += 1
            event = AuthEvent(
                event_type="simulated_blocked",
                username=f"attacker_{i:02d}",
                detail="rate_limited",
                ip=request.remote_addr,
            )
        else:
            record_attempt(sim_key)
            reached_password_check += 1
            event = AuthEvent(
                event_type="simulated_attack",
                username=f"attacker_{i:02d}",
                detail="reached_password_check",
                ip=request.remote_addr,
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
    return render_template("admin.html", users=users, events=events,
                           counts=counts, current_filter=event_filter)


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
    cutoff = datetime.utcnow() - timedelta(hours=24)
    counts = {}
    for event_type in [
        "signup_success", "signup_fail", "login_success_pending_2fa",
        "login_fail", "2fa_success", "2fa_fail", "logout",
        "simulated_attack", "simulated_blocked",
    ]:
        counts[event_type] = AuthEvent.query.filter_by(event_type=event_type).count()

    recent = AuthEvent.query.order_by(AuthEvent.timestamp.desc()).limit(20).all()
    last_hour = AuthEvent.query.filter(AuthEvent.timestamp >= cutoff).count()
    user_count = User.query.count()

    return jsonify({
        "counts": counts,
        "recent": [e.to_dict() for e in recent],
        "events_last_24h": last_hour,
        "total_users": user_count,
    })


if __name__ == "__main__":
    app.run(debug=True)

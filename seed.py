"""Seed test users for demoing the auth system.

Run: python seed.py

Re-running this script will REPLACE any existing test users with the same usernames,
so it's safe to use after manually creating accounts.
"""
import bcrypt

from app import app
from models import AuthEvent, EmailCode, User, db


TEST_USERS = [
    # (username, email, password, is_admin)
    ("admin",     "admin@securauth.demo",   "AdminPassword123!",  True),
    ("testuser",  "test@securauth.demo",    "TestPassword123!",   False),
    ("alice",     "alice@securauth.demo",   "AlicePassword123!",  False),
    ("bob",       "bob@securauth.demo",     "BobPassword123!",    False),
    ("demo",      "demo@securauth.demo",    "DemoPassword123!",   False),
]


def main():
    with app.app_context():
        db.create_all()
        for username, email, password, is_admin in TEST_USERS:
            existing = User.query.filter_by(username=username).first()
            if existing:
                EmailCode.query.filter_by(user_id=existing.id).delete()
                db.session.delete(existing)
                db.session.commit()
                print(f"  replaced  {username:12s}")
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            u = User(username=username, email=email, password_hash=pw_hash, is_admin=is_admin)
            db.session.add(u)
            tag = "admin" if is_admin else "user "
            print(f"  added     {username:12s}  [{tag}]  password={password}  email={email}")
        db.session.commit()
        print("\nDone. Email codes will be printed to the Flask console (or sent via SMTP if configured).")


if __name__ == "__main__":
    main()

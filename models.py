from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class EmailCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PendingSignup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuthEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(32), nullable=False)
    username = db.Column(db.String(64))
    detail = db.Column(db.String(255))
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    browser = db.Column(db.String(64))
    os_family = db.Column(db.String(64))
    device = db.Column(db.String(32))
    country = db.Column(db.String(64))
    city = db.Column(db.String(64))
    attack_vector = db.Column(db.String(32))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "username": self.username,
            "detail": self.detail,
            "ip": self.ip,
            "browser": self.browser,
            "os": self.os_family,
            "device": self.device,
            "country": self.country,
            "city": self.city,
            "attack_vector": self.attack_vector,
            "timestamp": self.timestamp.isoformat() + "Z",
        }

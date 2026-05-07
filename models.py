"""
Database models - Strict separation of file content and license metadata
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255))
    password_hash = db.Column(db.String(255), nullable=False)
    password_salt = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)

    licenses = db.relationship('License', backref='user', lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('UserSession', backref='user', lazy=True, cascade='all, delete-orphan')


class License(db.Model):
    """
    All DRM metadata lives here — NEVER embedded in the encrypted file.
    The encrypted_aes_key is RSA-encrypted so only the server can decrypt it.
    """
    __tablename__ = 'licenses'
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_name = db.Column(db.String(255))
    file_hash = db.Column(db.String(64))  # SHA-256 of original plaintext
    # RSA-encrypted AES key — stored server-side only
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    # GCM parameters — stored server-side only (NOT in the file)
    file_nonce = db.Column(db.String(64), nullable=False)
    file_tag = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer)
    uses_remaining = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=True)
    is_revoked = db.Column(db.Boolean, default=False)

    devices = db.relationship('LicenseDevice', backref='license', lazy=True, cascade='all, delete-orphan')


class LicenseDevice(db.Model):
    """
    Many-to-many: one license can authorize multiple devices.
    Device verification is always server-side.
    """
    __tablename__ = 'license_devices'
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(64), db.ForeignKey('licenses.license_id'), nullable=False, index=True)
    device_id = db.Column(db.String(255), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('license_id', 'device_id', name='uq_license_device'),
    )


class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_valid = db.Column(db.Boolean, default=True)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def init_db(app):
    with app.app_context():
        db.create_all()
        print("✅ Database tables created")

"""
SecureDRM - Database Models
Simple, clean, and production-ready
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

def init_db(app):
    """Initialize database with all tables"""
    with app.app_context():
        db.create_all()


class User(db.Model):
    """User account model"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    licenses = db.relationship('License', backref='owner', lazy=True)
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)


class UserSession(db.Model):
    """User session with device binding"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(32), db.ForeignKey('users.user_id'), nullable=False)
    device_id = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class License(db.Model):
    """DRM License - contains all encrypted file metadata"""
    __tablename__ = 'licenses'
    
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(32), db.ForeignKey('users.user_id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    file_nonce = db.Column(db.String(32), nullable=False)
    file_tag = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    max_uses = db.Column(db.Integer, nullable=True)
    uses_remaining = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_revoked = db.Column(db.Boolean, nullable=False, default=False)
    
    # Relationships
    authorized_devices = db.relationship('LicenseDevice', backref='license', lazy=True)


class LicenseDevice(db.Model):
    """Authorized devices for each license"""
    __tablename__ = 'license_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(32), db.ForeignKey('licenses.license_id'), nullable=False)
    device_id = db.Column(db.String(64), nullable=False, index=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('license_id', 'device_id', name='unique_license_device'),
        db.Index('idx_license_device', 'license_id', 'device_id'),
    )


class AuditLog(db.Model):
    """Audit log for security tracking"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_audit_user', 'user_id'),
        db.Index('idx_audit_action', 'action'),
        db.Index('idx_audit_created', 'created_at'),
    )
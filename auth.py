"""
User authentication with database
"""
import base64
import secrets
from datetime import datetime, timedelta

from models import db, User, UserSession
from crypto import CryptoUtils


class UserManagerDB:

    @staticmethod
    def register(username: str, password: str, email: str = None) -> dict:
        if User.query.filter_by(username=username).first():
            return {'success': False, 'message': 'Username already exists'}
        if len(password) < 8:
            return {'success': False, 'message': 'Password must be at least 8 characters'}

        pw_hash, salt = CryptoUtils.hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=base64.b64encode(pw_hash).decode(),
            password_salt=base64.b64encode(salt).decode(),
            is_active=True,
            failed_attempts=0
        )
        db.session.add(user)
        db.session.commit()
        return {'success': True, 'message': 'User registered successfully', 'user_id': user.id}

    @staticmethod
    def login(username: str, password: str, ip_address: str = None, user_agent: str = None) -> dict:
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_active:
            return {'success': False, 'message': 'Invalid credentials'}

        stored_hash = base64.b64decode(user.password_hash)
        salt = base64.b64decode(user.password_salt)

        if not CryptoUtils.verify_password(password, stored_hash, salt):
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.is_active = False
            db.session.commit()
            return {'success': False, 'message': 'Invalid credentials'}

        user.failed_attempts = 0
        user.last_login = datetime.utcnow()

        # Invalidate all old sessions
        UserSession.query.filter_by(user_id=user.id, is_valid=True).update({'is_valid': False})

        session_token = secrets.token_urlsafe(64)
        new_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True
        )
        db.session.add(new_session)
        db.session.commit()

        return {
            'success': True,
            'message': 'Login successful',
            'session_token': session_token,
            'user_id': user.id,
            'username': user.username
        }

    @staticmethod
    def validate_session(session_token: str) -> dict:
        if not session_token:
            return {'valid': False}
        session = UserSession.query.filter_by(session_token=session_token, is_valid=True).first()
        if not session:
            return {'valid': False}
        if datetime.utcnow() > session.expires_at:
            session.is_valid = False
            db.session.commit()
            return {'valid': False}
        user = User.query.get(session.user_id)
        if not user or not user.is_active:
            return {'valid': False}
        # Sliding expiry
        session.expires_at = datetime.utcnow() + timedelta(days=7)
        db.session.commit()
        return {'valid': True, 'user_id': user.id, 'username': user.username}

    @staticmethod
    def logout(session_token: str) -> bool:
        session = UserSession.query.filter_by(session_token=session_token).first()
        if session:
            session.is_valid = False
            db.session.commit()
            return True
        return False

"""
SecureDRM - Authentication Helper
Simple session management
"""
from models import UserSession, User
from datetime import datetime

class UserManagerDB:
    """Simple user session manager"""
    
    @staticmethod
    def validate_session(token: str) -> dict:
        """Validate session token"""
        session = UserSession.query.filter_by(
            session_token=token,
            is_active=True
        ).first()
        
        if not session:
            return None
        
        if datetime.utcnow() > session.expires_at:
            session.is_active = False
            from models import db
            db.session.commit()
            return None
        
        user = User.query.filter_by(user_id=session.user_id, is_active=True).first()
        if not user:
            return None
        
        return {
            'valid': True,
            'user_id': user.user_id,
            'username': user.username,
            'device_id': session.device_id
        }
    
    @staticmethod
    def revoke_session(token: str):
        """Revoke a session"""
        session = UserSession.query.filter_by(session_token=token).first()
        if session:
            session.is_active = False
            from models import db
            db.session.commit()
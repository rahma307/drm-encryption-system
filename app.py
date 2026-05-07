"""
SecureDRM - Digital Rights Management System
AES-256-GCM Encryption + RSA Key Wrapping + Device Binding
Version: Academic Final - Production Ready
"""
import os
import base64
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===================== CONFIG =====================
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database setup (SQLite for development, MySQL for production)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///drm.db')
if database_url.startswith("mysql://"):
    database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}

# ===================== DATABASE =====================
from models import db, User, License, LicenseDevice, UserSession, AuditLog, init_db

db.init_app(app)
with app.app_context():
    init_db(app)

# ===================== CRYPTO =====================
from crypto import AESHandler, RSAHandler, CryptoUtils

# Load RSA keys (generated once)
try:
    _private_key, _public_key = RSAHandler.load_or_generate_keys()
    print("✅ RSA keys ready")
except Exception as e:
    print(f"❌ RSA init failed: {e}")
    _private_key, _public_key = None, None


# ===================== AUTH DECORATORS =====================
def get_token():
    """Extract Bearer token from Authorization header"""
    auth = request.headers.get('Authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None


def get_current_user():
    """Get current user from session token"""
    token = get_token()
    if not token:
        return None
    
    session = UserSession.query.filter_by(
        session_token=token,
        is_active=True
    ).first()
    
    if not session:
        return None
    
    if datetime.utcnow() > session.expires_at:
        session.is_active = False
        db.session.commit()
        return None
    
    user = User.query.filter_by(user_id=session.user_id, is_active=True).first()
    if not user:
        return None
    
    return {
        'user_id': user.user_id,
        'username': user.username,
        'session_token': token,
        'device_id': session.device_id
    }


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return wrapper


# ===================== ROUTES =====================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/dashboard')
@require_auth
def dashboard():
    return render_template('dashboard.html')


@app.route('/encrypt')
@require_auth
def encrypt_page():
    return render_template('encrypt.html')


@app.route('/decrypt')
@require_auth
def decrypt_page():
    return render_template('decrypt.html')


# ===================== API - AUTH =====================
@app.route('/api/register', methods=['POST'])
def api_register():
    """Register a new user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        
        # Check if user exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        # Create user
        user_id = uuid.uuid4().hex
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        new_user = User(
            user_id=user_id,
            username=username,
            email=email if email else None,
            password_hash=password_hash,
            created_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': username
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    """Login user and create session with device binding"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        device_id = data.get('device_id', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        # Verify user
        user = User.query.filter_by(username=username, is_active=True).first()
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user.password_hash != password_hash:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Generate device ID from browser fingerprint if not provided
        if not device_id:
            ua = request.headers.get('User-Agent', '')
            ip = request.remote_addr or ''
            device_id = hashlib.sha256(f"{user.user_id}|{ua}|{ip}".encode()).hexdigest()[:32]
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        
        new_session = UserSession(
            session_token=session_token,
            user_id=user.user_id,
            device_id=device_id,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            ip_address=request.remote_addr,
            is_active=True
        )
        
        db.session.add(new_session)
        
        # Log login
        db.session.add(AuditLog(
            user_id=user.user_id,
            action='LOGIN',
            details=f'Device: {device_id[:32]}',
            ip_address=request.remote_addr
        ))
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session_token': session_token,
            'user_id': user.user_id,
            'username': user.username,
            'device_id': device_id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/logout', methods=['POST'])
@require_auth
def api_logout():
    """Logout user"""
    try:
        token = get_token()
        session = UserSession.query.filter_by(session_token=token).first()
        if session:
            session.is_active = False
            db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== API - ENCRYPT =====================
@app.route('/api/encrypt', methods=['POST'])
@require_auth
def api_encrypt():
    """Encrypt a file with DRM protection"""
    try:
        file = request.files.get('file')
        if not file or not file.filename:
            return jsonify({'success': False, 'error': 'No file provided'}), 400

        user_id = request.current_user['user_id']
        device_id = request.form.get('device_id', '').strip()
        
        if not device_id:
            device_id = request.current_user.get('device_id')
        
        if not device_id:
            return jsonify({'success': False, 'error': 'Device ID required'}), 400

        expiry_days = int(request.form.get('expiry_days', 7))
        max_uses_raw = request.form.get('max_uses', '').strip()
        max_uses = int(max_uses_raw) if max_uses_raw.isdigit() else None

        file_data = file.read()
        original_filename = secure_filename(file.filename)
        file_hash = CryptoUtils.calculate_file_hash(file_data)

        # Generate AES key and encrypt file
        aes_key = os.urandom(32)
        encrypted = AESHandler.encrypt(file_data, aes_key)

        # Encrypt AES key with RSA public key
        public_key = RSAHandler.load_public_key()
        encrypted_aes_key = RSAHandler.encrypt_key(aes_key, public_key)

        license_id = uuid.uuid4().hex

        new_license = License(
            license_id=license_id,
            user_id=user_id,
            file_name=original_filename,
            file_hash=file_hash,
            encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode(),
            file_nonce=base64.b64encode(encrypted['nonce']).decode(),
            file_tag=base64.b64encode(encrypted['tag']).decode(),
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=expiry_days),
            max_uses=max_uses,
            uses_remaining=max_uses,
            is_active=True,
            is_revoked=False
        )

        db.session.add(new_license)

        # Bind license to this device
        db.session.add(LicenseDevice(
            license_id=license_id, 
            device_id=device_id
        ))

        db.session.add(AuditLog(
            user_id=user_id,
            action='ENCRYPT',
            details=f'File: {original_filename}, License: {license_id}',
            ip_address=request.remote_addr
        ))

        db.session.commit()

        return jsonify({
            'success': True,
            'encrypted_file': base64.b64encode(encrypted['ciphertext']).decode(),
            'license_id': license_id,
            'expires_at': new_license.expires_at.isoformat(),
            'uses_remaining': new_license.uses_remaining,
            'original_filename': original_filename
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== API - DECRYPT =====================
@app.route('/api/decrypt', methods=['POST'])
@require_auth
def api_decrypt():
    """Decrypt a DRM-protected file with device verification"""
    try:
        user_id = request.current_user['user_id']
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400

        encrypted_file_b64 = data.get('encrypted_file', '').strip()
        license_id = data.get('license_id', '').strip()
        client_device_id = data.get('device_id', '').strip()

        if not encrypted_file_b64 or not license_id:
            return jsonify({'success': False, 'error': 'encrypted_file and license_id required'}), 400

        # Get device ID (from session or client)
        device_id = client_device_id
        if not device_id:
            device_id = request.current_user.get('device_id')
        
        if not device_id:
            return jsonify({'success': False, 'error': 'Device ID required'}), 400

        # Get license with row lock for atomic update
        lic = License.query.filter_by(license_id=license_id).with_for_update().first()

        if not lic:
            return jsonify({'success': False, 'error': 'License not found'}), 404

        # Check license ownership
        if lic.user_id != user_id:
            return jsonify({'success': False, 'error': 'License does not belong to user'}), 403

        # Check license status
        if lic.is_revoked:
            return jsonify({'success': False, 'error': 'License revoked'}), 403

        if not lic.is_active:
            return jsonify({'success': False, 'error': 'License inactive'}), 403

        if lic.expires_at and datetime.utcnow() > lic.expires_at:
            return jsonify({'success': False, 'error': 'License expired'}), 403

        # Check device authorization
        authorized_devices = LicenseDevice.query.filter_by(license_id=license_id).all()
        
        if authorized_devices:
            allowed_devices = {d.device_id for d in authorized_devices}
            if device_id not in allowed_devices:
                db.session.add(AuditLog(
                    user_id=user_id,
                    action='DECRYPT_DENIED',
                    details=f'Unauthorized device for license {license_id}',
                    ip_address=request.remote_addr
                ))
                db.session.commit()
                return jsonify({'success': False, 'error': 'Device not authorized for this license'}), 403

        # Check usage count
        if lic.max_uses is not None:
            if lic.uses_remaining <= 0:
                return jsonify({'success': False, 'error': 'License usage exhausted'}), 403

        # Decrypt the file
        try:
            ciphertext = base64.b64decode(encrypted_file_b64)
            db_nonce = base64.b64decode(lic.file_nonce)
            db_tag = base64.b64decode(lic.file_tag)
            encrypted_aes_key = base64.b64decode(lic.encrypted_aes_key)

            private_key = RSAHandler.load_private_key()
            aes_key = RSAHandler.decrypt_key(encrypted_aes_key, private_key)

            decrypted_data = AESHandler.decrypt(ciphertext, aes_key, db_nonce, db_tag)
        except Exception as e:
            return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'}), 400

        # Verify file integrity
        calculated_hash = CryptoUtils.calculate_file_hash(decrypted_data)
        if calculated_hash != lic.file_hash:
            return jsonify({'success': False, 'error': 'Integrity check failed - file may be corrupted'}), 400

        # Update usage count (atomic)
        if lic.max_uses is not None:
            lic.uses_remaining -= 1
            if lic.uses_remaining <= 0:
                lic.is_active = False

        # Log success
        db.session.add(AuditLog(
            user_id=user_id,
            action='DECRYPT',
            details=f'File: {lic.file_name}, License: {license_id}',
            ip_address=request.remote_addr
        ))

        db.session.commit()

        return jsonify({
            'success': True,
            'decrypted_file': base64.b64encode(decrypted_data).decode(),
            'original_filename': lic.file_name,
            'uses_remaining': lic.uses_remaining
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== API - USER DATA =====================
@app.route('/api/user/licenses', methods=['GET'])
@require_auth
def api_user_licenses():
    """Get all licenses for current user"""
    try:
        user_id = request.current_user['user_id']
        
        licenses = License.query.filter_by(user_id=user_id).order_by(License.created_at.desc()).all()
        
        result = []
        for lic in licenses:
            # Get authorized devices
            devices = LicenseDevice.query.filter_by(license_id=lic.license_id).all()
            authorized_devices = [d.device_id for d in devices]
            
            # Determine status
            if lic.is_revoked:
                status = 'revoked'
            elif not lic.is_active:
                status = 'inactive'
            elif lic.expires_at and datetime.utcnow() > lic.expires_at:
                status = 'expired'
            elif lic.max_uses and lic.uses_remaining <= 0:
                status = 'exhausted'
            else:
                status = 'active'
            
            result.append({
                'license_id': lic.license_id,
                'file_name': lic.file_name,
                'file_hash': lic.file_hash,
                'created_at': lic.created_at.isoformat(),
                'expires_at': lic.expires_at.isoformat() if lic.expires_at else None,
                'max_uses': lic.max_uses,
                'uses_remaining': lic.uses_remaining,
                'status': status,
                'authorized_devices': authorized_devices
            })
        
        return jsonify({
            'success': True,
            'licenses': result
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user/device', methods=['GET'])
@require_auth
def api_user_device():
    """Get current user's device info"""
    try:
        token = get_token()
        session = UserSession.query.filter_by(session_token=token, is_active=True).first()
        
        if not session:
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        return jsonify({
            'success': True,
            'device_id': session.device_id,
            'created_at': session.created_at.isoformat(),
            'expires_at': session.expires_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== API - LICENSE MANAGEMENT =====================
@app.route('/api/license/<license_id>/add-device', methods=['POST'])
@require_auth
def api_license_add_device():
    """Add a device to license's authorized devices"""
    try:
        user_id = request.current_user['user_id']
        license_id = request.view_args.get('license_id')
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400
        
        device_id = data.get('device_id', '').strip()
        
        if not device_id:
            return jsonify({'success': False, 'error': 'device_id required'}), 400
        
        # Check license ownership
        lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
        if not lic:
            return jsonify({'success': False, 'error': 'License not found'}), 404
        
        # Check if already authorized
        existing = LicenseDevice.query.filter_by(license_id=license_id, device_id=device_id).first()
        if existing:
            return jsonify({'success': False, 'error': 'Device already authorized'}), 400
        
        new_device = LicenseDevice(
            license_id=license_id,
            device_id=device_id,
            added_at=datetime.utcnow()
        )
        
        db.session.add(new_device)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Device added successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/license/<license_id>/remove-device', methods=['POST'])
@require_auth
def api_license_remove_device():
    """Remove a device from license's authorized devices"""
    try:
        user_id = request.current_user['user_id']
        license_id = request.view_args.get('license_id')
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400
        
        device_id = data.get('device_id', '').strip()
        
        if not device_id:
            return jsonify({'success': False, 'error': 'device_id required'}), 400
        
        # Check license ownership
        lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
        if not lic:
            return jsonify({'success': False, 'error': 'License not found'}), 404
        
        device_entry = LicenseDevice.query.filter_by(license_id=license_id, device_id=device_id).first()
        if not device_entry:
            return jsonify({'success': False, 'error': 'Device not found in license'}), 404
        
        db.session.delete(device_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Device removed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/license/<license_id>/revoke', methods=['POST'])
@require_auth
def api_license_revoke():
    """Revoke a license"""
    try:
        user_id = request.current_user['user_id']
        license_id = request.view_args.get('license_id')
        
        lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
        if not lic:
            return jsonify({'success': False, 'error': 'License not found'}), 404
        
        lic.is_revoked = True
        lic.is_active = False
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'License revoked successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== HEALTH CHECK =====================
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'encryption': 'AES-256-GCM + RSA-2048',
        'drm': 'device-binding-enabled',
        'features': ['encrypt', 'decrypt', 'license-management', 'audit-logs']
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
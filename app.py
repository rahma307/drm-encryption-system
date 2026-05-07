"""
SecureDRM - Production-Grade Digital Rights Management System
Encrypted files contain ZERO metadata. All DRM logic is server-side only.
"""
import pymysql
pymysql.install_as_MySQLdb()
import os
import base64
import json
import uuid
import tempfile
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===================== CONFIG =====================
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))

database_url = os.environ.get('DATABASE_URL', 'sqlite:///drm.db')

if database_url.startswith("mysql://"):
    database_url = database_url.replace(
        "mysql://",
        "mysql+pymysql://",
        1
    )

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

try:
    _private_key, _public_key = RSAHandler.load_or_generate_keys()
    print("✅ RSA keys ready")
except Exception as e:
    print(f"❌ RSA init failed: {e}")
    _private_key, _public_key = None, None

# ===================== AUTH =====================
from auth import UserManagerDB


def get_token():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def get_current_user():
    token = get_token()
    if not token:
        return None
    result = UserManagerDB.validate_session(token)
    return result if result and result.get('valid') else None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return wrapper


# ===================== PAGE ROUTES =====================
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
def dashboard():
    return render_template('dashboard.html')

@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')


# ===================== AUTH API =====================
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    result = UserManagerDB.register(username, password, email)
    if result['success']:
        return jsonify({'success': True, 'message': result['message']})
    return jsonify({'success': False, 'error': result['message']}), 400


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    result = UserManagerDB.login(
        username, password,
        request.remote_addr,
        request.headers.get('User-Agent')
    )

    if result['success']:
        return jsonify({
            'success': True,
            'session_token': result['session_token'],
            'user_id': result['user_id'],
            'username': result['username']
        })
    return jsonify({'success': False, 'error': result['message']}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    token = get_token()
    if token:
        UserManagerDB.logout(token)
    return jsonify({'success': True})


@app.route('/api/check-session', methods=['GET'])
def check_session():
    user = get_current_user()
    if not user:
        return jsonify({'authenticated': False}), 401
    return jsonify({
        'authenticated': True,
        'user_id': user['user_id'],
        'username': user['username']
    })


# ===================== LICENSE API =====================
@app.route('/api/user/licenses', methods=['GET'])
@require_auth
def api_get_licenses():
    user_id = request.current_user['user_id']
    licenses = License.query.filter_by(user_id=user_id).order_by(License.created_at.desc()).all()

    result = []
    now = datetime.utcnow()
    for lic in licenses:
        status = 'active'
        if lic.is_revoked:
            status = 'revoked'
        elif not lic.is_active:
            status = 'inactive'
        elif lic.expires_at and lic.expires_at < now:
            status = 'expired'
        elif lic.max_uses is not None and lic.uses_remaining is not None and lic.uses_remaining <= 0:
            status = 'exhausted'

        devices = [d.device_id for d in LicenseDevice.query.filter_by(license_id=lic.license_id).all()]

        result.append({
            'license_id': lic.license_id,
            'file_name': lic.file_name,
            'created_at': lic.created_at.isoformat() if lic.created_at else None,
            'expires_at': lic.expires_at.isoformat() if lic.expires_at else None,
            'max_uses': lic.max_uses,
            'uses_remaining': lic.uses_remaining,
            'is_active': lic.is_active,
            'is_revoked': lic.is_revoked,
            'status': status,
            'authorized_devices': devices
        })

    return jsonify({'success': True, 'licenses': result})


@app.route('/api/license/<license_id>/add-device', methods=['POST'])
@require_auth
def api_add_device(license_id):
    """Allow owner to add a new authorized device to a license"""
    user_id = request.current_user['user_id']
    lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
    if not lic:
        return jsonify({'success': False, 'error': 'License not found'}), 404

    data = request.get_json()
    device_id = data.get('device_id', '').strip()
    if not device_id:
        return jsonify({'success': False, 'error': 'device_id required'}), 400

    existing = LicenseDevice.query.filter_by(license_id=license_id, device_id=device_id).first()
    if existing:
        return jsonify({'success': True, 'message': 'Device already authorized'})

    new_device = LicenseDevice(license_id=license_id, device_id=device_id)
    db.session.add(new_device)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Device authorized'})


@app.route('/api/license/<license_id>/remove-device', methods=['POST'])
@require_auth
def api_remove_device(license_id):
    user_id = request.current_user['user_id']
    lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
    if not lic:
        return jsonify({'success': False, 'error': 'License not found'}), 404

    data = request.get_json()
    device_id = data.get('device_id', '').strip()

    LicenseDevice.query.filter_by(license_id=license_id, device_id=device_id).delete()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Device removed'})


@app.route('/api/license/<license_id>/revoke', methods=['POST'])
@require_auth
def api_revoke_license(license_id):
    user_id = request.current_user['user_id']
    lic = License.query.filter_by(license_id=license_id, user_id=user_id).first()
    if not lic:
        return jsonify({'success': False, 'error': 'License not found'}), 404

    lic.is_revoked = True
    lic.is_active = False
    db.session.commit()
    return jsonify({'success': True, 'message': 'License revoked'})


# ===================== ENCRYPT API =====================
@app.route('/api/encrypt', methods=['POST'])
@require_auth
def api_encrypt():
    """
    Encrypt a file. The output .drm file contains ONLY:
    - 12-byte nonce
    - 16-byte GCM auth tag
    - ciphertext
    NO metadata, user_id, device_id, or license info is embedded in the file.
    """
    try:
        file = request.files.get('file')
        if not file or not file.filename:
            return jsonify({'error': 'No file provided'}), 400

        user_id = request.current_user['user_id']
        expiry_days = int(request.form.get('expiry_days', 7))
        max_uses_raw = request.form.get('max_uses', '').strip()
        max_uses = int(max_uses_raw) if max_uses_raw.isdigit() else None
        # Optional: initial device to bind (can be empty for open/floating licenses)
        initial_device_id = request.form.get('device_id', '').strip() or None

        # Validate device_id length to prevent DB bloat attacks
        if initial_device_id and len(initial_device_id) > 128:
            return jsonify({'error': 'device_id exceeds maximum length of 128 characters'}), 400

        file_data = file.read()
        original_filename = secure_filename(file.filename)
        file_hash = CryptoUtils.calculate_file_hash(file_data)

        # Generate unique AES-256 key per file
        aes_key = os.urandom(32)

        # AES-256-GCM encrypt — produces ciphertext, nonce, tag
        encrypted = AESHandler.encrypt(file_data, aes_key)

        # Wrap AES key with server RSA-2048 public key (stored in DB, never in file)
        public_key = RSAHandler.load_public_key()
        encrypted_aes_key = RSAHandler.encrypt_key(aes_key, public_key)

        # Full UUID4 hex (32 chars) — no truncation avoids birthday collision risk
        license_id = uuid.uuid4().hex

        new_license = License(
            license_id=license_id,
            user_id=user_id,
            file_name=original_filename,
            file_hash=file_hash,
            encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode(),
            # nonce and tag stored server-side ONLY — never embedded in the output file.
            # During decryption the server retrieves these from the DB record;
            # the client has no way to supply or substitute them.
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

        if initial_device_id:
            db.session.add(LicenseDevice(license_id=license_id, device_id=initial_device_id))

        db.session.add(AuditLog(
            user_id=user_id,
            action='ENCRYPT',
            details=f'File: {original_filename}, License: {license_id}',
            ip_address=request.remote_addr
        ))
        db.session.commit()

        # ── OUTPUT FILE = PURE CIPHERTEXT ONLY ──
        # The .drm file contains zero metadata:
        #   no nonce, no tag, no license_id, no user_id, no filename.
        # Nonce + tag + encrypted AES key are stored in the database.
        # Without the license_id (which the user records separately) AND a valid
        # session + authorized device_id, the ciphertext cannot be decrypted.
        output_file = encrypted['ciphertext']

        return jsonify({
            'success': True,
            'encrypted_file': base64.b64encode(output_file).decode(),
            'license_id': license_id,
            'expires_at': new_license.expires_at.isoformat(),
            'uses_remaining': new_license.uses_remaining,
            'original_filename': original_filename
        })

    except Exception as e:
        db.session.rollback()
        print(f"ENCRYPT ERROR: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ===================== DECRYPT API =====================
@app.route('/api/decrypt', methods=['POST'])
@require_auth
def api_decrypt():
    """
    Decrypt a file. Client sends: session_token (header), license_id, device_id,
    encrypted_file (raw ciphertext — no embedded metadata).

    ALL cryptographic parameters (nonce, tag, AES key) come from the DATABASE only.
    The client-uploaded file supplies ONLY the ciphertext bytes.
    The server never trusts client-supplied nonce/tag.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400

        encrypted_file_b64 = data.get('encrypted_file', '').strip()
        license_id          = data.get('license_id', '').strip()
        device_id           = data.get('device_id', '').strip()

        if not encrypted_file_b64 or not license_id:
            return jsonify({'success': False, 'error': 'encrypted_file and license_id are required'}), 400

        # Validate and cap device_id length to prevent DB bloat attacks
        if len(device_id) > 128:
            return jsonify({'success': False, 'error': 'device_id exceeds maximum length'}), 400

        user_id = request.current_user['user_id']

        # ── 1. FETCH LICENSE — locked for update to prevent race conditions ──
        lic = License.query.filter_by(license_id=license_id).with_for_update().first()
        if not lic:
            _log_audit(user_id, 'DECRYPT_DENIED', f'License not found: {license_id}', request)
            return jsonify({'success': False, 'error': 'License not found'}), 404

        # ── 2. OWNERSHIP — user must own this license ──
        if lic.user_id != user_id:
            _log_audit(user_id, 'DECRYPT_DENIED', f'Ownership mismatch: license {license_id}', request)
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # ── 3. REVOCATION ──
        if lic.is_revoked:
            return jsonify({'success': False, 'error': 'License has been revoked'}), 403

        # ── 4. ACTIVE STATE ──
        if not lic.is_active:
            return jsonify({'success': False, 'error': 'License is inactive'}), 403

        # ── 5. EXPIRY ──
        if lic.expires_at and datetime.utcnow() > lic.expires_at:
            return jsonify({'success': False, 'error': 'License has expired'}), 403

        # ── 6. USAGE COUNT (checked before decryption, decremented after) ──
        if lic.max_uses is not None and lic.uses_remaining is not None:
            if lic.uses_remaining <= 0:
                return jsonify({'success': False, 'error': 'No remaining uses'}), 403

        # ── 7. DEVICE BINDING — enforced server-side only ──
        authorized_devices = LicenseDevice.query.filter_by(license_id=license_id).all()
        if authorized_devices:
            if not device_id:
                return jsonify({'success': False, 'error': 'Device ID required for this license'}), 403
            authorized_ids = {d.device_id for d in authorized_devices}
            if device_id not in authorized_ids:
                _log_audit(user_id, 'DECRYPT_DENIED',
                           f'Unauthorized device for license {license_id}: {device_id[:32]}', request)
                return jsonify({'success': False, 'error': 'Device not authorized for this license'}), 403
        # No registered devices → floating license: any authenticated owner device is allowed

        # ── 8. DECODE CIPHERTEXT (client supplies raw ciphertext only) ──
        try:
            ciphertext = base64.b64decode(encrypted_file_b64)
        except Exception:
            return jsonify({'success': False, 'error': 'Invalid base64 encoding'}), 400

        if len(ciphertext) == 0:
            return jsonify({'success': False, 'error': 'Empty ciphertext'}), 400

        # ── 9. RETRIEVE ALL CRYPTO PARAMETERS FROM DATABASE — never from client ──
        #
        # SECURITY: nonce and tag come exclusively from the DB record.
        # A client cannot substitute a forged nonce/tag to manipulate decryption.
        # The encrypted file on disk is pure ciphertext only.
        #
        try:
            db_nonce           = base64.b64decode(lic.file_nonce)
            db_tag             = base64.b64decode(lic.file_tag)
            encrypted_aes_key  = base64.b64decode(lic.encrypted_aes_key)
        except Exception:
            return jsonify({'success': False, 'error': 'Corrupted license record'}), 500

        if len(db_nonce) != 12:
            return jsonify({'success': False, 'error': 'Corrupted nonce in license'}), 500
        if len(db_tag) != 16:
            return jsonify({'success': False, 'error': 'Corrupted tag in license'}), 500

        # ── 10. DECRYPT AES KEY ──
        private_key = RSAHandler.load_private_key()
        try:
            aes_key = RSAHandler.decrypt_key(encrypted_aes_key, private_key)
        except Exception:
            return jsonify({'success': False, 'error': 'Failed to recover encryption key'}), 500

        # ── 11. AES-GCM DECRYPT (GCM tag authenticates ciphertext integrity) ──
        try:
            decrypted_data = AESHandler.decrypt(ciphertext, aes_key, db_nonce, db_tag)
        except ValueError:
            # GCM authentication failed — wrong ciphertext, tampered file, or wrong license
            _log_audit(user_id, 'DECRYPT_FAILED',
                       f'GCM auth failure for license {license_id}', request)
            return jsonify({'success': False, 'error': 'Decryption failed: file integrity check failed'}), 400

        # ── 12. OPTIONAL PLAINTEXT INTEGRITY CHECK against stored SHA-256 hash ──
        if lic.file_hash:
            actual_hash = CryptoUtils.calculate_file_hash(decrypted_data)
            if actual_hash != lic.file_hash:
                _log_audit(user_id, 'DECRYPT_INTEGRITY_FAIL',
                           f'Hash mismatch for license {license_id}', request)
                return jsonify({'success': False, 'error': 'File integrity verification failed'}), 400

        # ── 13. ATOMIC USAGE DECREMENT (lock already held via with_for_update) ──
        uses_after = None
        if lic.max_uses is not None and lic.uses_remaining is not None:
            lic.uses_remaining -= 1
            uses_after = lic.uses_remaining
            if lic.uses_remaining <= 0:
                lic.is_active = False

        _log_audit(user_id, 'DECRYPT',
                   f'File: {lic.file_name}, License: {license_id}, '
                   f'Device: {device_id[:32] if device_id else "floating"}', request)
        db.session.commit()

        # ── 14. RETURN DECRYPTED CONTENT ONLY — no metadata leakage ──
        return jsonify({
            'success': True,
            'decrypted_file': base64.b64encode(decrypted_data).decode(),
            'original_filename': lic.file_name,
            'uses_remaining': uses_after
        })

    except ValueError as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        print(f"DECRYPT ERROR: {e}")
        return jsonify({'success': False, 'error': 'Decryption failed'}), 500


def _log_audit(user_id, action, details, req):
    try:
        db.session.add(AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=req.remote_addr
        ))
    except Exception:
        pass


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'encryption': 'AES-256-GCM + RSA-2048', 'drm': 'server-side-only'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)

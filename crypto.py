"""
SecureDRM - Enterprise-Grade Cryptography Module
AES-256-GCM + RSA-2048 + Cryptographic Device Binding
"""
import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class CryptoUtils:
    @staticmethod
    def calculate_file_hash(data: bytes) -> str:
        """Calculate SHA-256 hash of file data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def calculate_device_id(public_key_spki: bytes) -> str:
        """Calculate device ID from public key (SHA-256)"""
        return hashlib.sha256(public_key_spki).hexdigest()
    
    @staticmethod
    def generate_challenge() -> str:
        """Generate crypto challenge for device verification"""
        return os.urandom(32).hex()


class AESHandler:
    """AES-256-GCM encryption handler"""
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> dict:
        """Encrypt data with AES-256-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return {
            'ciphertext': ciphertext[:-16],
            'tag': ciphertext[-16:],
            'nonce': nonce
        }
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt data with AES-256-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)


class RSAHandler:
    """RSA-2048 key handler for key wrapping"""
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key) -> str:
        """Serialize public key to PEM string"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    @staticmethod
    def deserialize_public_key(public_key_pem: str):
        """Deserialize public key from PEM string"""
        return serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    
    @staticmethod
    def load_or_generate_keys(key_path='keys/'):
        """Load or generate RSA keys"""
        os.makedirs(key_path, exist_ok=True)
        
        private_path = os.path.join(key_path, 'private.pem')
        public_path = os.path.join(key_path, 'public.pem')
        
        if os.path.exists(private_path) and os.path.exists(public_path):
            with open(private_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(public_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            return private_key, public_key
        
        private_key, public_key = RSAHandler.generate_key_pair()
        
        with open(private_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(public_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        return private_key, public_key
    
    @staticmethod
    def load_private_key():
        """Load private key from file"""
        private_key, _ = RSAHandler.load_or_generate_keys()
        return private_key
    
    @staticmethod
    def load_public_key():
        """Load public key from file"""
        _, public_key = RSAHandler.load_or_generate_keys()
        return public_key
    
    @staticmethod
    def encrypt_key(aes_key: bytes, public_key) -> bytes:
        """Encrypt AES key with RSA public key"""
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt_key(encrypted_key: bytes, private_key) -> bytes:
        """Decrypt AES key with RSA private key"""
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
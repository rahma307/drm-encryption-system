"""
Cryptographic primitives for SecureDRM
"""
import os
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESHandler:
    NONCE_SIZE = 12  # GCM standard

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> dict:
        if len(key) != 32:
            raise ValueError("AES-256 requires exactly 32-byte key")
        nonce = os.urandom(AESHandler.NONCE_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(data) + enc.finalize()
        return {'ciphertext': ciphertext, 'nonce': nonce, 'tag': enc.tag}

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256 requires exactly 32-byte key")
        if len(nonce) != AESHandler.NONCE_SIZE:
            raise ValueError("Invalid nonce")
        if len(tag) != 16:
            raise ValueError("Invalid GCM tag")
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        dec = cipher.decryptor()
        try:
            return dec.update(ciphertext) + dec.finalize()
        except Exception:
            raise ValueError("Decryption failed — invalid key, tag, or corrupted data")


class RSAHandler:
    KEY_SIZE = 2048
    PRIVATE_KEY_PATH = "keys/private_key.pem"
    PUBLIC_KEY_PATH = "keys/public_key.pem"

    @classmethod
    def load_or_generate_keys(cls):
        os.makedirs("keys", exist_ok=True)
        if os.path.exists(cls.PRIVATE_KEY_PATH) and os.path.exists(cls.PUBLIC_KEY_PATH):
            try:
                return cls.load_private_key(), cls.load_public_key()
            except Exception:
                pass
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=cls.KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        with open(cls.PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(cls.PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("🔑 New RSA key pair generated")
        return private_key, public_key

    @classmethod
    def load_private_key(cls):
        with open(cls.PRIVATE_KEY_PATH, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    @classmethod
    def load_public_key(cls):
        with open(cls.PUBLIC_KEY_PATH, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    @staticmethod
    def encrypt_key(aes_key: bytes, public_key) -> bytes:
        return public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def decrypt_key(encrypted_key: bytes, private_key) -> bytes:
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )


class CryptoUtils:
    @staticmethod
    def hash_password(password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(32)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode()), salt

    @staticmethod
    def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return hmac.compare_digest(kdf.derive(password.encode()), stored_hash)

    @staticmethod
    def calculate_file_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from scarlett.logger import logger


def generate_key_from_password(password: bytes, salt: bytes) -> bytes:
    logger.debug("Generating Fernet compatible key.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def generate_key() -> bytes:
    return Fernet.generate_key()


def encrypt(data: bytes, key: bytes):
    return Fernet(key).encrypt(data)


def decrypt(token: bytes, key: bytes):
    return Fernet(key).decrypt(token)


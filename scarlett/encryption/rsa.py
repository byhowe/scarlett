from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_key_pair(key_size=4096) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key: RSAPublicKey = private_key.public_key()
    return public_key, private_key


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )


def serialize_private_key(private_key: RSAPrivateKey, password: bytes = None) -> bytes:
    encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )


def load_public_key(pem: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )


def load_private_key(pem: bytes, password: bytes = None) -> RSAPrivateKey:
    return serialization.load_pem_private_key(
        pem,
        password=password,
        backend=default_backend()
    )


def encrypt(public_key: RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(private_key: RSAPrivateKey, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

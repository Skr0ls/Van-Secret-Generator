"""Pure secret generation functions.

These functions perform no I/O and never terminate the process: failures
surface as exceptions for the caller to handle.
"""

import base64
import secrets
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_random_string(length=32, characters=None):
    """Генерация случайной строки с заданной длиной и набором символов"""
    if characters is None:
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(characters) for _ in range(length))


def generate_jwt_hmac():
    """Генерация HMAC-секрета для JWT"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8")


def generate_rsa_key_pair():
    """Генерация пары RSA ключей (2048 бит)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return private_pem, public_pem


def generate_db_password(length=16):
    """Генерация сложного пароля для СУБД"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        password = "".join(secrets.choice(characters) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()" for c in password)
        ):
            return password

"""Tests for the secret generation functions."""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from secret_generator.generators import (
    generate_db_password,
    generate_jwt_hmac,
    generate_random_string,
    generate_rsa_key_pair,
)

ALLOWED_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"


@pytest.mark.parametrize("length", [8, 16, 32, 64])
def test_random_string_length(length):
    assert len(generate_random_string(length)) == length


def test_random_string_uses_allowed_alphabet():
    value = generate_random_string(200)
    assert all(char in ALLOWED_CHARACTERS for char in value)


def test_jwt_hmac_format():
    value = generate_jwt_hmac()
    # 32 random bytes encoded as URL-safe base64 (43 chars + optional padding).
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}=*", value)


def test_jwt_hmac_uniqueness():
    assert generate_jwt_hmac() != generate_jwt_hmac()


def test_db_password_complexity():
    for _ in range(20):
        password = generate_db_password()
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in "!@#$%^&*()" for c in password)


@pytest.mark.parametrize("length", [8, 16, 24])
def test_db_password_length(length):
    assert len(generate_db_password(length)) == length


def test_db_password_uniqueness():
    passwords = {generate_db_password() for _ in range(20)}
    assert len(passwords) == 20


def test_rsa_key_pair_pem_headers():
    private_pem, public_pem = generate_rsa_key_pair()
    assert private_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_rsa_key_pair_round_trip():
    private_pem, public_pem = generate_rsa_key_pair()

    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public_key = serialization.load_pem_public_key(public_pem.encode())

    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048
    assert private_key.public_key().public_numbers().e == 65537
    # The public PEM must correspond to the private key.
    assert public_key.public_numbers() == private_key.public_key().public_numbers()

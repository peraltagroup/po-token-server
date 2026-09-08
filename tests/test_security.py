"""Tests for security primitives: JWT, Fernet cipher, redaction."""

from __future__ import annotations

import pytest

from po_token_server.config import Settings
from po_token_server.security import (
    JWTError,
    JWTService,
    SecretCipher,
    constant_time_equals,
    generate_opaque_token,
    redact,
)


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        jwt_secret="unit-test-secret-0123456789abcdef0123456789",
        secret_key="unit-test-fernet-0123456789abcdef",
    )


def test_jwt_roundtrip():
    svc = JWTService(_settings())
    token = svc.create_access_token("user-1", email="a@b.com", name="A", is_admin=True)
    claims = svc.decode(token)
    assert claims.sub == "user-1"
    assert claims.email == "a@b.com"
    assert claims.name == "A"
    assert claims.is_admin is True
    assert claims.jti


def test_jwt_rejects_tampered_token():
    svc = JWTService(_settings())
    token = svc.create_access_token("user-1")
    # Flip a character in the signature.
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    with pytest.raises(JWTError):
        svc.decode(tampered)


def test_jwt_rejects_wrong_issuer():
    s1 = JWTService(_settings())
    s2 = Settings(
        _env_file=None,
        jwt_secret="unit-test-secret-0123456789abcdef0123456789",
        jwt_issuer="other-issuer",
    )
    s2svc = JWTService(s2)
    token = s1.create_access_token("user-1")
    # Decoding with a service expecting a different issuer must fail.
    with pytest.raises(JWTError):
        s2svc.decode(token)


def test_fernet_roundtrip():
    cipher = SecretCipher("some-key-material")
    secret = "google-refresh-token-xyz"
    enc = cipher.encrypt(secret)
    assert enc != secret
    assert cipher.decrypt(enc) == secret


def test_fernet_detects_invalid_token():
    cipher = SecretCipher("some-key-material")
    assert cipher.is_valid_token(cipher.encrypt("x")) is True
    assert cipher.is_valid_token("not-a-valid-token") is False


def test_fernet_different_keys_cannot_decrypt():
    c1 = SecretCipher("key-one")
    c2 = SecretCipher("key-two")
    enc = c1.encrypt("secret")
    with pytest.raises(Exception):
        c2.decrypt(enc)


def test_opaque_token_unique_and_length():
    a = generate_opaque_token()
    b = generate_opaque_token()
    assert a != b
    assert len(a) >= 32


def test_constant_time_equals():
    assert constant_time_equals("abc", "abc") is True
    assert constant_time_equals("abc", "abd") is False


def test_redact_masks_secrets_recursively():
    data = {
        "refresh_token": "secret1",
        "nested": {"access_token": "secret2", "ok": "visible"},
        "list": [{"password": "secret3"}, "plain"],
        "public": "shown",
    }
    out = redact(data)
    assert out["refresh_token"] == "***REDACTED***"
    assert out["nested"]["access_token"] == "***REDACTED***"
    assert out["nested"]["ok"] == "visible"
    assert out["list"][0]["password"] == "***REDACTED***"
    assert out["list"][1] == "plain"
    assert out["public"] == "shown"

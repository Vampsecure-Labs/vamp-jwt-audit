# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidos para los tests de vamp-jwt-audit
"""

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Utilidades para construir JWTs de prueba sin PyJWT
# ─────────────────────────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    """Codifica bytes en base64url sin padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def crear_jwt_alg_none(payload: dict) -> str:
    """Crea JWT con alg:none para tests (sin firma)."""
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    return f"{header}.{body}."


def crear_jwt_hs256(payload: dict, secret: str = "secret") -> str:
    """Crea JWT HS256 firmado con el secreto dado para tests."""
    import hashlib
    import hmac
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    mensaje = f"{header}.{body}".encode()
    firma = hmac.new(secret.encode(), mensaje, hashlib.sha256).digest()
    return f"{header}.{body}.{b64url(firma)}"


def crear_jwt_rs256_header(payload: dict) -> str:
    """Crea JWT con cabecera RS256 (firma falsa para tests de análisis de cabecera)."""
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}).encode())
    body = b64url(json.dumps(payload).encode())
    # Firma falsa para tests que no necesitan verificación real
    firma = b64url(b"firma_falsa_para_tests")
    return f"{header}.{body}.{firma}"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def payload_valido():
    """Payload JWT con todos los claims estándar presentes y válidos."""
    ahora = int(time.time())
    return {
        "sub": "user-123",
        "iss": "https://auth.vampsecure.test",
        "aud": "vampsecure-app",
        "iat": ahora - 300,
        "exp": ahora + 3600,
        "role": "user",
    }


@pytest.fixture
def payload_sin_exp():
    """Payload JWT sin claim de expiración."""
    return {"sub": "user-123", "iss": "auth.vampsecure.test", "aud": "app"}


@pytest.fixture
def payload_expirado():
    """Payload JWT con exp en el pasado."""
    ahora = int(time.time())
    return {
        "sub": "user-123",
        "iss": "https://auth.vampsecure.test",
        "aud": "vampsecure-app",
        "iat": ahora - 7200,
        "exp": ahora - 3600,
    }


@pytest.fixture
def payload_ttl_largo():
    """Payload JWT con TTL > 24h."""
    ahora = int(time.time())
    return {
        "sub": "user-123",
        "iss": "https://auth.vampsecure.test",
        "aud": "vampsecure-app",
        "iat": ahora,
        "exp": ahora + 90000,  # 25 horas
    }


@pytest.fixture
def payload_con_pii():
    """Payload JWT con datos PII en el payload."""
    ahora = int(time.time())
    return {
        "sub": "user-123",
        "iss": "https://auth.vampsecure.test",
        "aud": "vampsecure-app",
        "iat": ahora,
        "exp": ahora + 3600,
        "email": "test@vampsecure.test",
        "id_prueba": "123456789",
    }


@pytest.fixture
def payload_admin():
    """Payload JWT con role de alto privilegio."""
    ahora = int(time.time())
    return {
        "sub": "user-123",
        "iss": "https://auth.vampsecure.test",
        "aud": "vampsecure-app",
        "iat": ahora,
        "exp": ahora + 3600,
        "role": "admin",
    }


@pytest.fixture
def jwt_alg_none(payload_valido):
    """JWT con alg:none construido manualmente."""
    return crear_jwt_alg_none(payload_valido)


@pytest.fixture
def jwt_hs256_debil(payload_valido):
    """JWT HS256 firmado con el secreto débil 'secret'."""
    return crear_jwt_hs256(payload_valido, "secret")


@pytest.fixture
def jwt_rs256(payload_valido):
    """JWT RS256 con firma falsa para tests de análisis de cabecera."""
    return crear_jwt_rs256_header(payload_valido)

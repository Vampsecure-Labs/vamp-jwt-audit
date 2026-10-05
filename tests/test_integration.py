# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-jwt-audit
===============================================================
Verifica el flujo completo de audit_token con tokens construidos manualmente,
sin necesidad de servidor externo ni PyJWT.
"""

import pytest
import base64
import json
import time

import vamp_jwt_audit as jwt_mod
from vamp_jwt_audit import (
    audit_token, decode_jwt, analyze_claims, analyze_oauth_url,
)
from .conftest import crear_jwt_alg_none, crear_jwt_hs256, crear_jwt_rs256_header


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: JWT con alg:none → CRITICAL en audit_token
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationAlgNone:
    """Verifica que audit_token detecta alg:none como CRITICAL."""

    def test_jwt_alg_none_detectado_critical(self):
        """
        JWT creado manualmente con alg:none (base64url sin PyJWT).
        La tool debe detectarlo como CRITICAL sin servidor.
        """
        ahora = int(time.time())
        payload = {
            "sub": "attacker",
            "role": "admin",
            "iat": ahora,
            "exp": ahora + 3600,
        }
        token_none = crear_jwt_alg_none(payload)

        resultado = audit_token(token_none)

        # Debe haber al menos un finding CRITICAL por alg:none
        criticos = [f for f in resultado.findings if f.severity == "CRITICAL"]
        assert len(criticos) >= 1
        assert any("none" in f.title.lower() for f in criticos)

    def test_jwt_alg_none_token_generado_presente(self):
        """audit_token debe generar el token alg:none manipulado en el resultado."""
        ahora = int(time.time())
        payload = {"sub": "user", "exp": ahora + 3600}
        token_hs256 = crear_jwt_hs256(payload)

        resultado = audit_token(token_hs256)

        assert resultado.alg_none_token is not None
        assert resultado.alg_none_token.endswith(".")


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: JWT con secreto débil → CRITICAL (secreto encontrado)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationSecretoDebil:
    """Verifica que audit_token encuentra secretos débiles por fuerza bruta."""

    def test_secreto_secret_encontrado_como_critical(self):
        """Token HS256 con secreto 'secret' debe resultar en finding CRITICAL."""
        ahora = int(time.time())
        payload = {
            "sub": "user-456",
            "iss": "auth.test",
            "aud": "app",
            "exp": ahora + 3600,
        }
        token = crear_jwt_hs256(payload, "secret")

        resultado = audit_token(token)

        # El secreto debe haber sido encontrado
        assert resultado.cracked_secret == "secret"
        # Debe haber finding CRITICAL sobre el secreto
        criticos = [f for f in resultado.findings if f.severity == "CRITICAL"]
        assert any("secreto" in f.title.lower() or "secret" in f.title.lower()
                   for f in criticos)

    def test_secreto_password123_encontrado(self):
        """Token HS256 con secreto 'password123' debe encontrarse."""
        ahora = int(time.time())
        payload = {"sub": "x", "exp": ahora + 3600}
        token = crear_jwt_hs256(payload, "password123")

        resultado = audit_token(token)

        assert resultado.cracked_secret == "password123"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: JWT expirado → MEDIUM en claims
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationTokenExpirado:
    """Verifica que audit_token detecta tokens expirados."""

    def test_token_expirado_genera_finding_medium(self):
        """Un token con exp en el pasado debe generar finding MEDIUM."""
        ahora = int(time.time())
        payload = {
            "sub": "user-789",
            "iss": "auth.test",
            "aud": "app",
            "iat": ahora - 7200,
            "exp": ahora - 3600,  # Expirado hace 1h
        }
        token = crear_jwt_hs256(payload, "clave_fuerte_para_no_crackar_5843")

        resultado = audit_token(token)

        medios = [f for f in resultado.findings if f.severity == "MEDIUM"]
        assert any("expir" in f.title.lower() for f in medios)


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: analyze_oauth_url end-to-end — PKCE ausente
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationOAuthUrl:
    """Verifica la detección de problemas OAuth 2.0 en URLs de autorización."""

    def test_pkce_ausente_en_url_code_flow(self):
        """Una URL code flow sin code_challenge debe detectar ausencia de PKCE."""
        url = (
            "https://auth.vampsecure.test/oauth/authorize"
            "?client_id=mi-app&response_type=code"
            "&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback"
            "&state=Xk8mP3aQ2n"
            "&scope=openid+profile"
        )
        hallazgos = analyze_oauth_url(url)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("pkce" in f.title.lower() or "code_challenge" in f.title.lower()
                   for f in altos)

    def test_implicit_flow_url_detectado(self):
        """Una URL con response_type=token (implicit) debe generar finding HIGH."""
        url = (
            "https://auth.vampsecure.test/oauth/authorize"
            "?client_id=mi-spa&response_type=token"
            "&redirect_uri=https%3A%2F%2Fspa.test%2Fcallback"
            "&state=Xk8mP3aQ2n"
        )
        hallazgos = analyze_oauth_url(url)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("implicit" in f.title.lower() or "token" in f.title.lower()
                   for f in altos)


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Token sin exp → HIGH en audit_token completo
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationSinExp:
    """Verifica que audit_token detecta ausencia de expiración como HIGH."""

    def test_token_sin_exp_genera_high(self):
        """Un token sin claim 'exp' debe generar finding HIGH."""
        payload = {"sub": "service-account", "iss": "internal", "aud": "api"}
        token = crear_jwt_hs256(payload, "clave_fuerte_5843_no_en_diccionario")

        resultado = audit_token(token)

        altos = [f for f in resultado.findings if f.severity == "HIGH"]
        assert any("exp" in f.title.lower() or "expiración" in f.title.lower()
                   for f in altos)

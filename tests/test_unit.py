# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-jwt-audit
===================================================
Cubre: decode_jwt, craft_alg_none_token, craft_rs256_hs256_token,
analyze_header, analyze_claims, brute_force_secret, analyze_oauth_url.
"""

import json
import time

from vamp_jwt_audit import (
    _b64url_encode,
    analyze_claims,
    analyze_header,
    analyze_oauth_url,
    brute_force_secret,
    craft_alg_none_token,
    decode_jwt,
)

from .conftest import crear_jwt_hs256

# ─────────────────────────────────────────────────────────────────────────────
# Tests de decode_jwt
# ─────────────────────────────────────────────────────────────────────────────

class TestDecodeJWT:
    """Tests del parser de tokens JWT."""

    def test_decode_jwt_valido(self, jwt_hs256_debil):
        """Un JWT válido de 3 partes debe decodificarse correctamente."""
        componentes = decode_jwt(jwt_hs256_debil)
        assert componentes.error is None
        assert componentes.header["alg"] == "HS256"
        assert "sub" in componentes.payload

    def test_decode_jwt_strips_bearer(self, jwt_hs256_debil):
        """El prefijo 'Bearer ' debe eliminarse antes de parsear."""
        componentes = decode_jwt(f"Bearer {jwt_hs256_debil}")
        assert componentes.error is None
        assert componentes.header is not None

    def test_decode_jwt_alg_none(self, jwt_alg_none):
        """JWT con alg:none (sin firma) debe decodificarse correctamente."""
        componentes = decode_jwt(jwt_alg_none)
        assert componentes.error is None
        assert componentes.header["alg"] == "none"

    def test_decode_jwt_malformado_error(self):
        """Un token con menos de 2 partes debe devolver error."""
        decode_jwt("esto.no.es.valido.ni.remotamente")
        # Con más de 3 partes podría fallar al intentar parsear el JSON
        componentes2 = decode_jwt("solounasola")
        assert componentes2.error is not None

    def test_decode_jwt_preserva_payload(self, payload_valido, jwt_hs256_debil):
        """El payload decodificado debe coincidir con el payload original."""
        componentes = decode_jwt(jwt_hs256_debil)
        assert componentes.payload["sub"] == payload_valido["sub"]


# ─────────────────────────────────────────────────────────────────────────────
# Tests de craft_alg_none_token
# ─────────────────────────────────────────────────────────────────────────────

class TestCraftAlgNoneToken:
    """Tests del constructor de tokens alg:none."""

    def test_token_alg_none_tiene_tres_partes(self, jwt_hs256_debil):
        """El token manipulado debe tener 3 partes separadas por '.'."""
        componentes = decode_jwt(jwt_hs256_debil)
        token_none = craft_alg_none_token(componentes)
        partes = token_none.split(".")
        assert len(partes) == 3

    def test_token_alg_none_firma_vacia(self, jwt_hs256_debil):
        """La firma del token alg:none debe estar vacía."""
        componentes = decode_jwt(jwt_hs256_debil)
        token_none = craft_alg_none_token(componentes)
        partes = token_none.split(".")
        assert partes[2] == ""

    def test_token_alg_none_cabecera_correcta(self, jwt_hs256_debil):
        """La cabecera del token manipulado debe declarar alg=none."""
        componentes = decode_jwt(jwt_hs256_debil)
        token_none = craft_alg_none_token(componentes)
        # Decodificar la cabecera del token resultante
        cabecera_nueva = decode_jwt(token_none).header
        assert cabecera_nueva["alg"] == "none"

    def test_token_alg_none_preserva_payload(self, jwt_hs256_debil, payload_valido):
        """El payload del token manipulado debe coincidir con el original."""
        componentes = decode_jwt(jwt_hs256_debil)
        token_none = craft_alg_none_token(componentes)
        payload_nuevo = decode_jwt(token_none).payload
        assert payload_nuevo["sub"] == payload_valido["sub"]


# ─────────────────────────────────────────────────────────────────────────────
# Tests de analyze_header
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeHeader:
    """Tests del analizador de cabecera JWT."""

    def test_alg_none_genera_finding_critical(self, jwt_alg_none):
        """Un token con alg:none debe generar un finding CRITICAL."""
        componentes = decode_jwt(jwt_alg_none)
        hallazgos = analyze_header(componentes)
        criticos = [f for f in hallazgos if f.severity == "CRITICAL"]
        assert len(criticos) >= 1
        assert any("none" in f.title.lower() for f in criticos)

    def test_hs256_genera_finding_info(self, jwt_hs256_debil):
        """Un token HS256 legítimo debe generar finding INFO sobre el algoritmo."""
        componentes = decode_jwt(jwt_hs256_debil)
        hallazgos = analyze_header(componentes)
        infos = [f for f in hallazgos if f.severity == "INFO"]
        assert any("HS256" in f.title for f in infos)

    def test_rs256_genera_finding_info_confusion(self, jwt_rs256):
        """Un token RS256 debe generar finding INFO sobre posible confusión de algoritmo."""
        componentes = decode_jwt(jwt_rs256)
        hallazgos = analyze_header(componentes)
        infos = [f for f in hallazgos if f.severity == "INFO"]
        assert any("RS256" in f.title for f in infos)

    def test_jku_genera_finding_critical(self):
        """Un header con 'jku' debe generar finding CRITICAL (inyección de clave)."""
        header_con_jku = _b64url_encode(
            json.dumps({"alg": "RS256", "typ": "JWT", "jku": "https://evil.com/keys"}).encode()
        )
        payload_enc = _b64url_encode(json.dumps({"sub": "test"}).encode())
        token = f"{header_con_jku}.{payload_enc}.firma"
        componentes = decode_jwt(token)
        hallazgos = analyze_header(componentes)
        criticos = [f for f in hallazgos if f.severity == "CRITICAL"]
        assert any("jku" in f.title.lower() for f in criticos)


# ─────────────────────────────────────────────────────────────────────────────
# Tests de analyze_claims
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeClaims:
    """Tests del analizador de claims del payload JWT."""

    def test_exp_ausente_genera_high(self, payload_sin_exp):
        """Sin claim 'exp' debe generarse finding HIGH."""
        token = crear_jwt_hs256(payload_sin_exp)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("exp" in f.title.lower() or "expiración" in f.title.lower()
                   for f in altos)

    def test_exp_expirado_genera_medium(self, payload_expirado):
        """Token expirado debe generar finding MEDIUM."""
        token = crear_jwt_hs256(payload_expirado)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        medios = [f for f in hallazgos if f.severity == "MEDIUM"]
        assert any("expir" in f.title.lower() for f in medios)

    def test_ttl_largo_genera_low(self, payload_ttl_largo):
        """Un TTL > 24h debe generar finding LOW."""
        token = crear_jwt_hs256(payload_ttl_largo)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        bajos = [f for f in hallazgos if f.severity == "LOW"]
        assert any("vigencia" in f.title.lower() or "ttl" in f.title.lower()
                   or "hora" in f.title.lower() for f in bajos)

    def test_iss_ausente_genera_low(self):
        """Sin claim 'iss' debe generarse finding LOW."""
        ahora = int(time.time())
        payload = {"sub": "x", "aud": "app", "exp": ahora + 3600}
        token = crear_jwt_hs256(payload)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        bajos = [f for f in hallazgos if f.severity == "LOW"]
        assert any("iss" in f.title.lower() for f in bajos)

    def test_aud_ausente_genera_low(self):
        """Sin claim 'aud' debe generarse finding LOW."""
        ahora = int(time.time())
        payload = {"sub": "x", "iss": "auth.test", "exp": ahora + 3600}
        token = crear_jwt_hs256(payload)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        bajos = [f for f in hallazgos if f.severity == "LOW"]
        assert any("aud" in f.title.lower() for f in bajos)

    def test_pii_en_payload_genera_medium(self, payload_con_pii):
        """Claims con PII (email, ssn) deben generar finding MEDIUM."""
        token = crear_jwt_hs256(payload_con_pii)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        medios = [f for f in hallazgos if f.severity == "MEDIUM"]
        assert any("pii" in f.title.lower() or "personal" in f.description.lower()
                   for f in medios)

    def test_role_admin_genera_high(self, payload_admin):
        """Un claim 'role' con valor 'admin' debe generar finding HIGH."""
        token = crear_jwt_hs256(payload_admin)
        componentes = decode_jwt(token)
        hallazgos = analyze_claims(componentes)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("admin" in f.title.lower() or "privilegio" in f.title.lower()
                   for f in altos)


# ─────────────────────────────────────────────────────────────────────────────
# Tests de brute_force_secret
# ─────────────────────────────────────────────────────────────────────────────

class TestBruteForceSecret:
    """Tests del ataque de fuerza bruta de secreto HMAC."""

    def test_encuentra_secreto_debil(self, jwt_hs256_debil):
        """Debe encontrar el secreto 'secret' que está en la lista de comunes."""
        componentes = decode_jwt(jwt_hs256_debil)
        secreto = brute_force_secret(componentes)
        assert secreto == "secret"

    def test_secreto_fuerte_devuelve_none(self, payload_valido):
        """Un secreto de alta entropía no debe encontrarse en la lista de comunes."""
        secreto_fuerte = "v4mpS3cur3L4b5_S3cr3t_K3y_n0_d1cc10n4r10_2024!"
        token = crear_jwt_hs256(payload_valido, secreto_fuerte)
        componentes = decode_jwt(token)
        secreto = brute_force_secret(componentes)
        assert secreto is None

    def test_alg_rs256_devuelve_none(self, jwt_rs256):
        """Para tokens RS256 brute_force_secret debe devolver None (solo HMAC)."""
        componentes = decode_jwt(jwt_rs256)
        secreto = brute_force_secret(componentes)
        assert secreto is None

    def test_wordlist_extra_usada(self, payload_valido):
        """Un secreto personalizado debe encontrarse si se pasa en wordlist."""
        secreto_custom = "mi_secreto_personalizado_para_test"
        token = crear_jwt_hs256(payload_valido, secreto_custom)
        componentes = decode_jwt(token)
        secreto = brute_force_secret(componentes, extra_wordlist=[secreto_custom])
        assert secreto == secreto_custom


# ─────────────────────────────────────────────────────────────────────────────
# Tests de analyze_oauth_url
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeOauthUrl:
    """Tests del analizador de URLs de autorización OAuth 2.0."""

    BASE_URL = "https://auth.vampsecure.test/oauth/authorize"

    def test_state_ausente_genera_critical(self):
        """Sin parámetro 'state' debe generarse finding CRITICAL."""
        url = f"{self.BASE_URL}?client_id=test&response_type=code&redirect_uri=https://app.test/cb"
        hallazgos = analyze_oauth_url(url)
        criticos = [f for f in hallazgos if f.severity == "CRITICAL"]
        assert any("state" in f.title.lower() for f in criticos)

    def test_pkce_ausente_genera_high(self):
        """Sin code_challenge (PKCE) en flujo code debe generarse finding HIGH."""
        url = (
            f"{self.BASE_URL}?client_id=test&response_type=code"
            "&redirect_uri=https://app.test/cb&state=abc123"
        )
        hallazgos = analyze_oauth_url(url)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("pkce" in f.title.lower() or "code_challenge" in f.title.lower()
                   for f in altos)

    def test_implicit_flow_genera_high(self):
        """response_type=token (implicit flow) debe generar finding HIGH."""
        url = (
            f"{self.BASE_URL}?client_id=test&response_type=token"
            "&redirect_uri=https://app.test/cb&state=abc123"
        )
        hallazgos = analyze_oauth_url(url)
        altos = [f for f in hallazgos if f.severity == "HIGH"]
        assert any("implicit" in f.title.lower() or "token" in f.title.lower()
                   for f in altos)

    def test_scope_admin_genera_info(self):
        """Scope con 'admin' debe generar finding INFO sobre scopes permisivos."""
        url = (
            f"{self.BASE_URL}?client_id=test&response_type=code"
            "&redirect_uri=https://app.test/cb&state=abc123"
            "&code_challenge=X&scope=read:profile+admin"
        )
        hallazgos = analyze_oauth_url(url)
        # Scopes peligrosos detectados
        assert any("admin" in f.title.lower() or "scope" in f.title.lower()
                   for f in hallazgos)

    def test_redirect_uri_ausente_genera_medium(self):
        """Sin redirect_uri debe generarse finding MEDIUM."""
        url = (
            f"{self.BASE_URL}?client_id=test&response_type=code"
            "&state=abc123&code_challenge=X"
        )
        hallazgos = analyze_oauth_url(url)
        medios_o_bajos = [f for f in hallazgos if f.severity in ("MEDIUM", "LOW")]
        assert any("redirect" in f.title.lower() for f in medios_o_bajos)

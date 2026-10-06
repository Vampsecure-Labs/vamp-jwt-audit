# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, secretos y dataclasses del auditor JWT
"""

from __future__ import annotations

from dataclasses import dataclass, field

VERSION   = "1.4.0"
TOOL_NAME = "vamp-jwt-audit"

# =============================================================================
# SECRETOS COMUNES PARA FUERZA BRUTA
# =============================================================================

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
    header:  dict  = field(default_factory=dict)
    payload: dict  = field(default_factory=dict)
    sig_b64: str   = ""
    parts:   list  = field(default_factory=list)
    error:   str | None = None


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
    components: JWTComponents | None = None
    findings:   list[Finding]           = field(default_factory=list)
    cracked_secret: str | None       = None
    alg_none_token: str | None       = None
    rs256_hs256_token: str | None    = None
    # Token RS256→HS256 generado con clave pública obtenida automáticamente del JWKS
    jwks_rs256_hs256_token: str | None = None
    jwks_pubkey_pem: str | None        = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return self.findings[0].severity

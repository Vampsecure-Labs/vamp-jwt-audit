# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_jwt_audit — Auditor de seguridad JWT (librería importable + CLI)

API pública
-----------
  audit_token(token, wordlist, pubkey_pem, jwks_url) -> AuditResult
  decode_jwt(token) -> JWTComponents
  analyze_header(components) -> list[Finding]
  analyze_claims(components) -> list[Finding]
  analyze_oauth_url(url) -> list[Finding]
  brute_force_secret(components, extra_wordlist) -> str | None
  craft_alg_none_token(components) -> str
  craft_rs256_hs256_token(components, pubkey_pem) -> str | None
  to_json(results) -> str
  to_html(results) -> str
"""

from ._models import (
    VERSION,
    TOOL_NAME,
    _COMMON_SECRETS,  # noqa: F401
    JWTComponents,
    Finding,
    AuditResult,
)
from ._core import (
    _b64url_decode,
    _b64url_encode,
    _jwk_rsa_to_pem,  # noqa: F401
    fetch_jwks_public_key,
    decode_jwt,
    craft_alg_none_token,
    craft_rs256_hs256_token,
    brute_force_secret,
    analyze_claims,
    analyze_header,
    detect_vulnerable_frameworks,
    _test_kid_injection,  # noqa: F401
    _test_jku_injection,  # noqa: F401
    analyze_oauth_url,
    audit_token,
)
from ._report import (
    SEVERITY_STYLE_HTML,  # noqa: F401
    to_json,
    to_html,
    _findings_vsl,  # noqa: F401
)
from .cli import main

__all__ = [
    "VERSION", "TOOL_NAME",
    "JWTComponents", "Finding", "AuditResult",
    "audit_token", "decode_jwt",
    "analyze_header", "analyze_claims", "analyze_oauth_url",
    "brute_force_secret",
    "craft_alg_none_token", "craft_rs256_hs256_token",
    "fetch_jwks_public_key",
    "detect_vulnerable_frameworks",
    "_b64url_decode", "_b64url_encode",
    "to_json", "to_html",
    "main",
]

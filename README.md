<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-jwt-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-jwt-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

## Overview

`vamp-jwt-audit` is a JWT (JSON Web Token) security auditor that tests tokens for the full range of documented attack classes: `alg=none` bypass, RS256-to-HS256 algorithm confusion, HMAC brute-force against a 200+ entry built-in wordlist, header injection attacks (`jku`, `x5u`, `jwk`, `kid`), and claims-level security issues. It accepts tokens from the command line, a file, or standard input — making it easy to slot into proxies, CI pipelines, or capture-the-flag workflows. The optional `cryptography` library unlocks the RS256-to-HS256 attack when a public key is supplied.

## Features

- Six-phase attack sequence: decode without verification, header analysis, claims analysis, craft `alg=none` token, HMAC brute-force, RS256→HS256 confusion
- Built-in wordlist with 200+ common secrets including framework defaults, Docker/Kubernetes defaults, and the empty string
- Header injection checks: `alg=none` (CRITICAL), `jku`/`x5u` key URL injection (CRITICAL), inline `jwk` (CRITICAL), `kid` path traversal and SQL injection patterns (CRITICAL)
- Claims security checks: missing `exp` (HIGH), expired token (MEDIUM), TTL > 24 hours (LOW), `nbf` in future (MEDIUM), missing `iss`/`aud` (LOW), privileged role claims (HIGH), PII in payload (MEDIUM)
- RS256→HS256 confusion attack: forges a valid-looking HS256 token signed with the RSA public key (requires `--pubkey` and `cryptography`)
- Custom wordlist support (`--wordlist`) with automatic fallback to the built-in list
- Supports single token (`--token`), file of tokens (`--file`), and stdin pipeline mode (`--stdin`)
- Export to Console (Rich panels), JSON, and HTML (dark-theme)

## Requirements

- Python 3.9 or later
- `rich >= 13.7.0`
- Optional: `cryptography >= 41.0` — required for `--pubkey` (RS256→HS256 confusion attack)

## Installation


```bash
pip install vamp-jwt-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-jwt-audit
```

```bash
git clone https://github.com/belky-me/vamp-jwt-audit.git
cd vamp-jwt-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# For RS256→HS256 attack support:
pip install cryptography
```

## Usage

```
python3 vamp_jwt_audit.py --help
```

```
usage: vamp_jwt_audit.py [-h]
  Token source (mutually exclusive):
    --token JWT, -t JWT
    --file FILE, -f FILE
    --stdin

  Attack options:
    --wordlist FILE, -w FILE
    --pubkey FILE
    --no-bruteforce

  Output:
    --json FILE
    --html FILE
    --quiet
    --client CLIENT --engagement ENGAGEMENT --auditor AUDITOR
    --report-scope SCOPE --report-html FILE --report-pdf FILE

vamp-jwt-audit — JWT Security Auditor (VampSecure Labs)
```

## Examples

```bash
# Audit a single token passed directly
python3 vamp_jwt_audit.py --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Read token from file
python3 vamp_jwt_audit.py --file captured_token.txt

# Pipe a token from another tool
cat token.txt | python3 vamp_jwt_audit.py --stdin

# Use a custom wordlist for HMAC brute-force
python3 vamp_jwt_audit.py --token <JWT> --wordlist /path/to/secrets.txt

# Run RS256→HS256 confusion attack using a captured public key
python3 vamp_jwt_audit.py --token <JWT> --pubkey server_pubkey.pem

# Skip brute-force (faster static analysis only)
python3 vamp_jwt_audit.py --token <JWT> --no-bruteforce

# Export findings to JSON and HTML
python3 vamp_jwt_audit.py --token <JWT> --json results.json --html report.html

# Generate client-ready engagement report
python3 vamp_jwt_audit.py --file tokens.txt \
    --client "Acme Corp" --engagement "JWT Implementation Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--token / -t JWT` | — | JWT token string (mutually exclusive with `--file`/`--stdin`) |
| `--file / -f FILE` | — | File containing one or more JWT tokens |
| `--stdin` | — | Read token from standard input |
| `--wordlist / -w FILE` | built-in (200+) | Custom wordlist for HMAC brute-force |
| `--pubkey FILE` | — | RSA/EC public key PEM file for RS256→HS256 confusion |
| `--no-bruteforce` | off | Skip HMAC brute-force phase |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--quiet` | off | Suppress banner |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich panels with decoded header/payload, attack results, and severity ratings |
| JSON | `--json FILE` | Machine-readable full result set including forged token strings |
| HTML | `--html FILE` | Dark-theme standalone report |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

## Sample Output

```
$ python3 vamp_jwt_audit.py --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.abc123

╔══════════════════════════════════════════════════════════╗
║           vamp-jwt-audit — VampSecure Labs               ║
╚══════════════════════════════════════════════════════════╝

┌─── Decoded Header ────────────────────────────────────────────────────┐
│  alg: HS256   typ: JWT                                                │
└───────────────────────────────────────────────────────────────────────┘
┌─── Decoded Payload ────────────────────────────────────────────────────┐
│  sub: user_123   role: admin   iat: 2023-11-14T22:13:20Z              │
└───────────────────────────────────────────────────────────────────────┘

Phase 1 — alg=none bypass ............ CRITICAL: forged token accepted
  alg=none token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJhZG1pbiJ9.

Phase 2 — Header injection ........... CRITICAL: jku injection candidate
  jku: https://attacker.example.com/.well-known/jwks.json
  → server may fetch external JWKS and accept forged RSA key

Phase 3 — Claims analysis ............ HIGH: privileged role claim detected
  role=admin — escalation vector if server trusts this claim without RBAC verification

Phase 4 — HMAC brute-force ........... HIGH: secret found in built-in wordlist
  Secret: "secret"
  Forged HS256 token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJhZG1pbiJ9.FORGED

┌────────────────────────────────────────────────────────┐
│  CRITICAL  2   HIGH  2   MEDIUM  0   LOW  1   INFO  0  │
└────────────────────────────────────────────────────────┘
Exit code: 2  (CRITICAL findings — immediate action required)
```

---

## Why vamp-jwt-audit vs. jwt_tool · jwt.io · OWASP ZAP JWT addon

| Feature | vamp-jwt-audit | jwt_tool | jwt.io | ZAP JWT addon |
|---------|:---:|:---:|:---:|:---:|
| `alg=none` bypass detection | ✅ | ✅ | ❌ | ✅ |
| RS256→HS256 algorithm confusion | ✅ | ✅ | ❌ | ❌ |
| HMAC brute-force (200+ built-in wordlist) | ✅ | ✅ | ❌ | ❌ |
| `jku` / `x5u` / `jwk` / `kid` injection checks | ✅ | ✅ | ❌ | ⚠️ partial |
| Claims-level security analysis | ✅ | ❌ | ❌ | ❌ |
| CI/CD exit codes (0 / 1 / 2) | ✅ | ❌ | ❌ | ❌ |
| Client-ready HTML + PDF engagement report | ✅ | ❌ | ❌ | ❌ |
| Importable Python package | ✅ | ❌ | ❌ | ❌ |
| stdin / file batch mode | ✅ | ✅ | ❌ | ❌ |

- **jwt_tool** is the closest competitor and covers most attack classes, but produces terminal-only output with no structured JSON schema and no engagement report; integrating it into a CI pipeline requires wrapping it manually.
- **jwt.io** is a browser-based decoder/signer — useful for manual inspection but not scriptable, with no attack capabilities and no CI integration.
- **OWASP ZAP JWT addon** runs in the context of a proxy scan and tests tokens passively; it does not perform active attacks like RS256→HS256 confusion or HMAC brute-force against a standalone token.
- vamp-jwt-audit is the only tool in this comparison that combines active attacks, claims analysis, structured JSON output, and a client-delivery PDF report in a single pipeline-ready command.

---

## Check Coverage

| Check ID | Description | Severity | Standard |
|----------|-------------|----------|----------|
| JWT-001 | `alg=none` bypass — unsigned token accepted by the server | CRITICAL | RFC 7519 §8 / OWASP ASVS V3.5.8 |
| JWT-002 | `jku` header injection — attacker-controlled JWKS URL | CRITICAL | RFC 7515 §4.1.2 |
| JWT-003 | `x5u` header injection — attacker-controlled certificate URL | CRITICAL | RFC 7515 §4.1.5 |
| JWT-004 | Inline `jwk` header — key embedded inside the token itself | CRITICAL | RFC 7515 §4.1.3 |
| JWT-005 | RS256→HS256 algorithm confusion attack | CRITICAL | CVE-2015-9235 pattern / OWASP ASVS V3.5 |
| JWT-006 | HMAC secret brute-force — weak or default secret found | HIGH | OWASP ASVS V3.5.4 |
| JWT-007 | `kid` path traversal pattern detected in header | CRITICAL | OWASP ASVS V3.5.7 |
| JWT-008 | `kid` SQL injection pattern detected in header | CRITICAL | OWASP ASVS V3.5.7 |
| JWT-009 | Missing `exp` claim — token never expires | HIGH | RFC 7519 §4.1.4 |
| JWT-010 | Privileged role claim (`admin`, `superuser`, `root`, `god`) | HIGH | OWASP ASVS V3.5 |
| JWT-011 | PII in payload (email, SSN, phone number patterns) | MEDIUM | GDPR Art. 5 / OWASP ASVS V3.5 |
| JWT-012 | TTL > 24 hours — long-lived token | LOW | OWASP ASVS V3.5.1 |

---

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-jwt-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division

## Versión
v1.3.0 — VampSecure Labs Security Research Division

<h1 align="center">vamp-jwt-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
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

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-jwt-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division

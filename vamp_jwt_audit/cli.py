# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Interfaz de línea de comandos del auditor JWT (I/O, rich, argparse)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ._models import VERSION, TOOL_NAME, AuditResult, t
import vamp_jwt_audit._models as _models
from ._core import audit_token, analyze_oauth_url
from ._report import to_json, to_html, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-jwt-audit v1.5.0 · JWT Security Auditor
  ────────────────────────────────────────────────────────────────────────
  FOR AUTHORIZED SECURITY AUDITS ONLY · Unauthorized use is illegal
"""

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}


def print_token_detail(result: AuditResult) -> None:
    """Imprime en consola el detalle completo de un AuditResult."""
    components = result.components
    if not components or components.error:
        console.print(f"[bold red]  {t('Error', 'Error')}: {components.error if components else t('invalid token', 'token inválido')}[/]")
        return

    h_table = Table(title="JWT Header", show_lines=False, border_style="dim")
    h_table.add_column("Claim", style="cyan", width=12)
    h_table.add_column(t("Value", "Valor"))
    for k, v in components.header.items():
        h_table.add_row(k, json.dumps(v) if not isinstance(v, str) else v)
    console.print(h_table)

    p_table = Table(title="JWT Payload", show_lines=False, border_style="dim")
    p_table.add_column("Claim", style="cyan", width=18)
    p_table.add_column(t("Value", "Valor"))
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
                info += "  (" + (
                    t(f"in {abs(delta)}s", f"en {abs(delta)}s")
                    if delta > 0 else
                    t(f"EXPIRED {abs(delta)}s ago", f"EXPIRADO hace {abs(delta)}s")
                ) + ")"
        p_table.add_row(k, json.dumps(v) if not isinstance(v, str) else v, info)
    console.print(p_table)

    if components.sig_b64:
        console.print(f"  [dim]{t('Signature (base64url)', 'Firma (base64url)')}:[/] {components.sig_b64[:40]}{'...' if len(components.sig_b64) > 40 else ''}")

    if result.findings:
        console.print(f"\n  [bold]{t('FINDINGS:', 'HALLAZGOS:')}[/]")
    for f in result.findings:
        sev_color = SEVERITY_COLOR.get(f.severity, "white")
        console.print(Panel(
            f"{f.description}"
            + (f"\n\n[dim]{t('Evidence', 'Evidencia')}:[/] {f.evidence}" if f.evidence else "")
            + (f"\n\n[dim]{t('Remediation', 'Remediación')}:[/] {f.remediation}" if f.remediation else ""),
            title=f"[{sev_color}][{f.severity}][/] {f.title}",
            border_style="red" if f.severity == "CRITICAL" else "yellow" if f.severity == "HIGH" else "dim",
        ))

    if result.alg_none_token:
        console.print(f"\n  [dim]{t('Token alg=none (for manual testing)', 'Token alg=none (para prueba manual)')}:[/]")
        console.print(f"  [dim]{result.alg_none_token[:100]}...[/]" if len(result.alg_none_token) > 100 else f"  [dim]{result.alg_none_token}[/]")

    if result.cracked_secret is not None:
        console.print(f"\n  [bold red]⚠ {t('HMAC secret found', 'Secreto HMAC encontrado')}:[/] [bold]{result.cracked_secret!r}[/]")

    if result.rs256_hs256_token:
        console.print(f"\n  [bold yellow]{t('RS256→HS256 token generated (test on server)', 'Token RS256→HS256 generado (probar en el servidor)')}:[/]")
        console.print(f"  {result.rs256_hs256_token[:80]}...")

    if result.jwks_rs256_hs256_token:
        console.print(f"\n  [bold red][JWT-CONF-010] {t('RS256→HS256 token with real JWKS key (CRITICAL)', 'Token RS256→HS256 con clave JWKS real (CRITICAL)')}:[/]")
        console.print(f"  {result.jwks_rs256_hs256_token[:80]}...")


def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs JWT Audit v{VERSION} — "
            "JSON Web Token security analysis: "
            "decoding, alg=none, RS256→HS256 (with real JWKS key), "
            "secret brute-force, claims analysis, "
            "Hono detection (CVE-2026-22817) and OpenBao/Vault (CVE-2026-33757). "
            "Use --lang es for Spanish output."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx
  %(prog)s --token <JWT> --wordlist secrets.txt
  %(prog)s --token <JWT> --pubkey pub.pem
  %(prog)s --token <JWT> --jwks-url https://auth.example.com
  %(prog)s --token <JWT> --jwks-url https://auth.example.com/.well-known/jwks.json
  %(prog)s --file tokens.txt --json output.json --html output.html
  cat token.txt | %(prog)s --stdin
  %(prog)s --token <JWT> --lang es
        """,
    )

    src = p.add_argument_group("Token source")
    grp = src.add_mutually_exclusive_group(required=False)
    grp.add_argument("--token",  "-t", metavar="JWT",
                     help="JWT token to audit (on the command line)")
    grp.add_argument("--file",   "-f", metavar="FILE",
                     help="Text file with one JWT token per line")
    grp.add_argument("--stdin",        action="store_true",
                     help="Read token(s) from stdin (one token per line)")

    atk = p.add_argument_group("Attack options")
    atk.add_argument("--wordlist", "-w", metavar="FILE",
                     help="Additional wordlist for HMAC secret brute-force")
    atk.add_argument("--pubkey", metavar="FILE",
                     help="RSA PEM public key for generating an RS256→HS256 token")
    atk.add_argument("--jwks-url", metavar="URL",
                     help=(
                         "JWKS URL or OIDC issuer to automatically fetch the server's public key "
                         "and execute the RS256→HS256 confusion attack with the real key "
                         "(JWT-CONF-010, CVE-2026-22817). "
                         "If omitted, the token's 'iss' claim is tried when it is an HTTP URL. "
                         "Also activates Hono (CVE-2026-22817) and "
                         "OpenBao/Vault (CVE-2026-33757) detection by reading response headers."
                     ))
    atk.add_argument("--no-bruteforce", action="store_true",
                     help="Skip the secret brute-force phase (faster)")
    atk.add_argument("--oauth-url", metavar="URL",
                     help=(
                         "OAuth 2.0 authorization URL to analyse (no network request is made). "
                         "Checks: state (CSRF), code_challenge (PKCE), response_type=token (implicit flow), "
                         "redirect_uri and permissive scopes. Compatible with --token (joint analysis) or standalone."
                     ))

    out = p.add_argument_group("Output")
    out.add_argument("--json", metavar="FILE", help="Save results as JSON")
    out.add_argument("--html", metavar="FILE", help="Save dark-theme HTML report")
    out.add_argument("--quiet", action="store_true", help="Suppress banner")
    out.add_argument("--lang", choices=["en", "es"], default="en",
                     help="Output language: en (default) or es (Spanish)")

    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


def main() -> None:
    """Punto de entrada principal."""
    args = parse_args()
    _models.LANG = getattr(args, "lang", "en")

    if not getattr(args, "quiet", False):
        console.print(BANNER, style="bold magenta")

    tokens: list[str] = []
    if args.token:
        tokens = [args.token.strip()]
    elif args.file:
        fp = Path(args.file)
        if not fp.exists():
            console.print(f"[bold red]  ERROR: {t('File not found', 'Fichero no encontrado')}: {args.file}[/]")
            sys.exit(1)
        tokens = [l.strip() for l in fp.read_text(encoding="utf-8").splitlines() if l.strip()]
    elif args.stdin:
        tokens = [l.strip() for l in sys.stdin.readlines() if l.strip()]

    oauth_url = getattr(args, "oauth_url", None)
    if oauth_url:
        console.rule(f"[bold magenta]{t('OAuth 2.0 URL Analysis', 'Análisis OAuth 2.0 URL')}[/]")
        console.print(f"  [bold]URL:[/] {oauth_url[:120]}{'...' if len(oauth_url) > 120 else ''}")
        oauth_findings = analyze_oauth_url(oauth_url)
        if oauth_findings:
            from rich.table import Table as _Table
            tbl = _Table(show_header=True, header_style="bold dim", expand=True)
            tbl.add_column(t("Severity", "Severidad"), width=10)
            tbl.add_column(t("Title", "Título"))
            for f in oauth_findings:
                color = {"CRITICAL": "bold red", "HIGH": "bold yellow",
                         "MEDIUM": "bold magenta", "LOW": "cyan", "INFO": "green"}.get(f.severity, "white")
                tbl.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f.title,
                )
            console.print(tbl)
            for f in oauth_findings:
                if f.evidence:
                    console.print(f"  [dim]{t('Evidence', 'Evidencia')}: {f.evidence[:200]}[/]")
                if f.remediation:
                    from rich.panel import Panel as _Panel
                    console.print(_Panel(f.remediation, title=t("Remediation", "Remediación"), border_style="dim"))
        else:
            console.print(f"  [green]{t('No findings in the analysed OAuth URL.', 'Sin hallazgos en el URL OAuth analizado.')}[/]")
        console.print()

    if not tokens:
        if oauth_url:
            sys.exit(0)
        console.print(f"[bold red]  ERROR: {t('No JWT tokens or --oauth-url provided.', 'No se han proporcionado tokens JWT ni --oauth-url.')}[/]")
        sys.exit(1)

    wordlist: list[str] | None = None
    if args.wordlist and not args.no_bruteforce:
        wp = Path(args.wordlist)
        if not wp.exists():
            console.print(f"[yellow]  ⚠ {t('Wordlist not found', 'Wordlist no encontrada')}: {args.wordlist}[/]")
        else:
            wordlist = [l.strip() for l in wp.read_text(encoding="utf-8").splitlines() if l.strip()]
            console.print(f"  [dim]{t('Wordlist loaded', 'Wordlist cargada')}: {len(wordlist)} {t('secrets', 'secretos')}[/]")

    pubkey_pem: str | None = None
    if args.pubkey:
        pk_path = Path(args.pubkey)
        if not pk_path.exists():
            console.print(f"[yellow]  ⚠ {t('Public key not found', 'Clave pública no encontrada')}: {args.pubkey}[/]")
        else:
            pubkey_pem = pk_path.read_text(encoding="utf-8")
            console.print(f"  [dim]{t('Public key loaded', 'Clave pública cargada')}: {args.pubkey}[/]")

    jwks_url_arg: str | None = getattr(args, "jwks_url", None)
    if jwks_url_arg:
        console.print(f"  [dim]JWKS URL: {jwks_url_arg}[/]")

    results: list[AuditResult] = []
    for i, token in enumerate(tokens, 1):
        if len(tokens) > 1:
            console.print(f"\n[bold cyan]  ── {t(f'Token {i}/{len(tokens)}', f'Token {i}/{len(tokens)}')} ──[/]")

        result = audit_token(
            token,
            wordlist=wordlist if not args.no_bruteforce else None,
            pubkey_pem=pubkey_pem,
            jwks_url=jwks_url_arg,
        )
        results.append(result)
        print_token_detail(result)

    total_findings = sum(len(r.findings) for r in results)
    crit = sum(1 for r in results for f in r.findings if f.severity == "CRITICAL")
    high = sum(1 for r in results for f in r.findings if f.severity == "HIGH")
    cracked = sum(1 for r in results if r.cracked_secret is not None)

    sev_style = "bold red" if crit > 0 else ("bold yellow" if high > 0 else "bold green")
    console.print(
        f"\n[{sev_style}]  {t('SUMMARY', 'RESUMEN')}: {len(results)} {t('token(s)', 'token(s)')} · "
        f"{total_findings} {t('findings', 'hallazgos')} · {crit} {t('CRITICAL', 'CRÍTICO')} · {high} {t('HIGH', 'ALTO')}"
        + (f" · {cracked} {t('secret(s) found', 'secreto(s) descubierto(s)')}" if cracked else "")
        + "[/]"
    )

    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"[green]  ✔ {t('JSON saved', 'JSON guardado')}: {args.json}[/]")

    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]  ✔ {t('HTML saved', 'HTML guardado')}: {args.html}[/]")

    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        report  = VampSecReport(meta=meta, findings=_findings_vsl(results))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(f"[green]  ✔ {t('Client HTML report', 'Informe cliente HTML')}: {args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"[green]  ✔ {t('Client PDF report', 'Informe cliente PDF')}: {args.report_pdf}[/]")

    if crit > 0:
        sys.exit(2)
    elif high > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n[dim]  {t('Audit interrupted.', 'Auditoría interrumpida.')}[/]")
        sys.exit(130)

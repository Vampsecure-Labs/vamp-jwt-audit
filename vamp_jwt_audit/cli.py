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

from ._models import VERSION, TOOL_NAME, AuditResult
from ._core import audit_token, analyze_oauth_url
from ._report import to_json, to_html, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-jwt-audit v1.4.0 · JWT Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
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
        console.print(f"[bold red]  Error: {components.error if components else 'token inválido'}[/]")
        return

    h_table = Table(title="JWT Header", show_lines=False, border_style="dim")
    h_table.add_column("Claim", style="cyan", width=12)
    h_table.add_column("Valor")
    for k, v in components.header.items():
        h_table.add_row(k, json.dumps(v) if not isinstance(v, str) else v)
    console.print(h_table)

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

    if components.sig_b64:
        console.print(f"  [dim]Firma (base64url):[/] {components.sig_b64[:40]}{'...' if len(components.sig_b64) > 40 else ''}")

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

    if result.alg_none_token:
        console.print("\n  [dim]Token alg=none (para prueba manual):[/]")
        console.print(f"  [dim]{result.alg_none_token[:100]}...[/]" if len(result.alg_none_token) > 100 else f"  [dim]{result.alg_none_token}[/]")

    if result.cracked_secret is not None:
        console.print(f"\n  [bold red]⚠ Secreto HMAC encontrado:[/] [bold]{result.cracked_secret!r}[/]")

    if result.rs256_hs256_token:
        console.print("\n  [bold yellow]Token RS256→HS256 generado (probar en el servidor):[/]")
        console.print(f"  {result.rs256_hs256_token[:80]}...")

    if result.jwks_rs256_hs256_token:
        console.print("\n  [bold red][JWT-CONF-010] Token RS256→HS256 con clave JWKS real (CRITICAL):[/]")
        console.print(f"  {result.jwks_rs256_hs256_token[:80]}...")


def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs JWT Audit v{VERSION} — "
            "Análisis de seguridad de JSON Web Tokens: "
            "decodificación, alg=none, RS256→HS256 (con clave JWKS real), "
            "fuerza bruta de secreto, análisis de claims, "
            "detección de Hono (CVE-2026-22817) y OpenBao/Vault (CVE-2026-33757)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s --token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx
  %(prog)s --token <JWT> --wordlist secretos.txt
  %(prog)s --token <JWT> --pubkey pub.pem
  %(prog)s --token <JWT> --jwks-url https://auth.ejemplo.com
  %(prog)s --token <JWT> --jwks-url https://auth.ejemplo.com/.well-known/jwks.json
  %(prog)s --file tokens.txt --json salida.json --html salida.html
  cat token.txt | %(prog)s --stdin
        """,
    )

    src = p.add_argument_group("Origen del token")
    grp = src.add_mutually_exclusive_group(required=False)
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
    atk.add_argument("--jwks-url", metavar="URL",
                     help=(
                         "URL del JWKS o issuer OIDC para obtener la clave pública del servidor "
                         "automáticamente y ejecutar el ataque de confusión RS256→HS256 con la "
                         "clave real (JWT-CONF-010, CVE-2026-22817). "
                         "Si se omite, se intenta con el claim 'iss' del token si es una URL HTTP. "
                         "También activa la detección de Hono (CVE-2026-22817) y "
                         "OpenBao/Vault (CVE-2026-33757) leyendo las cabeceras de respuesta."
                     ))
    atk.add_argument("--no-bruteforce", action="store_true",
                     help="Omitir fase de fuerza bruta de secreto (más rápido)")
    atk.add_argument("--oauth-url", metavar="URL",
                     help=(
                         "URL de autorización OAuth 2.0 a analizar (sin realizar petición de red). "
                         "Comprueba: state (CSRF), code_challenge (PKCE), response_type=token (flujo implícito), "
                         "redirect_uri y scopes permisivos. Compatible con --token (análisis conjunto) o solo."
                     ))

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

    tokens: list[str] = []
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

    oauth_url = getattr(args, "oauth_url", None)
    if oauth_url:
        console.rule("[bold magenta]Análisis OAuth 2.0 URL[/]")
        console.print(f"  [bold]URL:[/] {oauth_url[:120]}{'...' if len(oauth_url) > 120 else ''}")
        oauth_findings = analyze_oauth_url(oauth_url)
        if oauth_findings:
            from rich.table import Table as _Table
            tbl = _Table(show_header=True, header_style="bold dim", expand=True)
            tbl.add_column("Severidad", width=10)
            tbl.add_column("Título")
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
                    console.print(f"  [dim]Evidencia: {f.evidence[:200]}[/]")
                if f.remediation:
                    from rich.panel import Panel as _Panel
                    console.print(_Panel(f.remediation, title="Remediación", border_style="dim"))
        else:
            console.print("  [green]Sin hallazgos en el URL OAuth analizado.[/]")
        console.print()

    if not tokens:
        if oauth_url:
            sys.exit(0)
        console.print("[bold red]  ERROR: No se han proporcionado tokens JWT ni --oauth-url.[/]")
        sys.exit(1)

    wordlist: list[str] | None = None
    if args.wordlist and not args.no_bruteforce:
        wp = Path(args.wordlist)
        if not wp.exists():
            console.print(f"[yellow]  ⚠ Wordlist no encontrada: {args.wordlist}[/]")
        else:
            wordlist = [l.strip() for l in wp.read_text(encoding="utf-8").splitlines() if l.strip()]
            console.print(f"  [dim]Wordlist cargada: {len(wordlist)} secretos[/]")

    pubkey_pem: str | None = None
    if args.pubkey:
        pk_path = Path(args.pubkey)
        if not pk_path.exists():
            console.print(f"[yellow]  ⚠ Clave pública no encontrada: {args.pubkey}[/]")
        else:
            pubkey_pem = pk_path.read_text(encoding="utf-8")
            console.print(f"  [dim]Clave pública cargada: {args.pubkey}[/]")

    jwks_url_arg: str | None = getattr(args, "jwks_url", None)
    if jwks_url_arg:
        console.print(f"  [dim]JWKS URL: {jwks_url_arg}[/]")

    results: list[AuditResult] = []
    for i, token in enumerate(tokens, 1):
        if len(tokens) > 1:
            console.print(f"\n[bold cyan]  ── Token {i}/{len(tokens)} ──[/]")

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
        f"\n[{sev_style}]  RESUMEN: {len(results)} token(s) · "
        f"{total_findings} hallazgos · {crit} CRÍTICO · {high} ALTO"
        + (f" · {cracked} secreto(s) descubierto(s)" if cracked else "")
        + "[/]"
    )

    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"[green]  ✔ JSON guardado: {args.json}[/]")

    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]  ✔ HTML guardado: {args.html}[/]")

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

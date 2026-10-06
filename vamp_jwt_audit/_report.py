# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Serialización de resultados: JSON, HTML, informe VSL unificado
"""

from __future__ import annotations

import json

from ._models import VERSION, TOOL_NAME, AuditResult

SEVERITY_STYLE_HTML = {
    "CRITICAL": "#ff2222",
    "HIGH":     "#ffcc00",
    "MEDIUM":   "#cc44ff",
    "LOW":      "#4af",
    "INFO":     "#4caf50",
}


def to_json(results: list[AuditResult]) -> str:
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
            "cracked_secret":         r.cracked_secret,
            "alg_none_token":         r.alg_none_token,
            "rs256_hs256_token":      r.rs256_hs256_token,
            "jwks_rs256_hs256_token": r.jwks_rs256_hs256_token,
        })
    return json.dumps({"generated_by": TOOL_NAME, "version": VERSION, "results": out},
                       indent=2, ensure_ascii=False)


def to_html(results: list[AuditResult]) -> str:
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

        h_rows = "".join(
            f"<tr><td class='claim'>{esc(k)}</td><td><code>{esc(json.dumps(v) if not isinstance(v, str) else v)}</code></td></tr>"
            for k, v in r.components.header.items()
        )
        p_rows = "".join(
            f"<tr><td class='claim'>{esc(k)}</td><td><code>{esc(json.dumps(v) if not isinstance(v, str) else v)}</code></td></tr>"
            for k, v in r.components.payload.items()
        )

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

def _findings_vsl(results: list[AuditResult]) -> list:
    """
    Convierte los AuditResult al formato Finding de vampsec_report.
    Solo se incluyen hallazgos de severidad MEDIUM, HIGH o CRITICAL.
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

"""Rapport HTML du mode WebScan Kali (structure héritée de html_report).

Même look que le rapport statique (hero score, cartes, badges, @media print
A4) mais adapté aux résultats web : résultat par outil (statut, durée,
nombre de findings), findings groupés par outil et table de préflight.
"""

import html
from datetime import datetime

from scanner.models import level_for
from reports.html_report import (
    SEV_COLORS, LEVEL_COLORS, GRADE_COLORS, _badge,
)
from kali.exploits import resolve_simple_explanation

# Libellés français des catégories (réutilisation du rapport statique).
_CAT_LABELS = {
    "injection": "Injection (SQL / commande)",
    "xss": "Cross-Site Scripting (XSS)",
    "security_misc": "Sécurité diverse",
    "secrets": "Secrets exposés",
    "dependencies": "Dépendances (CVE)",
    "code_quality": "Qualité de code",
    "performance": "Performance / asynchrone",
}


def _hero_block(score: dict) -> str:
    """Bloc « hero » du score web /100 (parité avec le rapport statique)."""
    sc = score.get("score", 0)
    grade = score.get("grade", "F")
    color = GRADE_COLORS.get(grade, "#95a5a6")
    total = score.get("total_findings", 0)
    tools = score.get("files_scanned", 0)
    return f"""
    <div class="hero">
      <div class="hero-left">
        <div class="hero-score"><span class="score-num">{sc}</span>
          <span class="score-total">/100</span></div>
      </div>
      <div class="hero-right">
        <div class="hero-grade" style="color:{color};border-color:{color}">{grade}</div>
        <div class="hero-label">Score web (dette sécurité)</div>
        <div class="hero-bar"><div class="hero-fill"
             style="width:{sc}%;background:{color}"></div></div>
        <div class="hero-sub">{total} relevés · {tools} outil(s) lancé(s)</div>
      </div>
    </div>"""


def _summary_cards(stats: dict, score: dict, by_tool: dict) -> str:
    """Cartes de synthèse : relevés, niveaux, outils."""
    by_level = score.get("by_level", {})
    cards = [
        ("Relevés", stats.get("total_findings", 0), "#38bdf8"),
        ("Critiques", by_level.get("CRITIQUE", 0), "#c0392b"),
        ("À revoir", by_level.get("À REVOIR", 0), "#e67e22"),
        ("MINEUR", by_level.get("MINEUR", 0), "#27ae60"),
        ("Outils OK", sum(1 for t in by_tool.values() if t.get("ok")), "#10b981"),
    ]
    out = []
    for label, num, color in cards:
        out.append(
            f'<div class="card" style="border-top:4px solid {color}">'
            f'<div class="card-num">{num}</div>'
            f'<div class="card-label">{label}</div></div>'
        )
    return f'<div class="cards">{"".join(out)}</div>'


def _tool_table(by_tool: dict) -> str:
    """Tableau résultat par outil (statut, durée, findings)."""
    rows = []
    for name, info in by_tool.items():
        status = info.get("status", "?")
        ok = info.get("ok")
        color = "#2ecc71" if ok else ("#e67e22" if status == "timeout" else "#e74c3c")
        dur = info.get("duration_sec", 0)
        rows.append(
            f"<tr><td class='mono'>{html.escape(name)}</td>"
            f"<td><span style='color:{color}'>{html.escape(str(status))}</span></td>"
            f"<td class='num'>{dur:.0f}s</td>"
            f"<td class='num'>{info.get('count', 0)}</td></tr>"
        )
    return "<table class='tooltable'><tr><th>Outil</th><th>Statut</th>" \
           "<th>Durée</th><th>Findings</th></tr>" + "".join(rows) + "</table>"


def _preflight_table(preflight: dict) -> str:
    """Table de préflight (binaire présent/absent)."""
    rows = []
    for name, info in preflight.items():
        present = info.get("present", False)
        mark = "✓" if present else "✗"
        color = "#2ecc71" if present else "#e74c3c"
        rows.append(
            f"<tr><td class='mono'>{html.escape(name)}</td>"
            f"<td><span style='color:{color}'>{mark}</span> "
            f"{'présent' if present else 'manquant'}</td>"
            f"<td class='mono'>{html.escape(info.get('bin', ''))}</td></tr>"
        )
    return "<table class='tooltable'><tr><th>Outil</th><th>Préflight</th>" \
           "<th>Binaire</th></tr>" + "".join(rows) + "</table>"


def _tool_sections(findings, by_tool: dict) -> str:
    """Findings groupés par outil (ordre du registre), avec badges niveau."""
    # Regroupement par source.
    by_source = {}
    for f in findings:
        by_source.setdefault(f.source, []).append(f)

    sections = []
    for name in by_tool:
        items = by_source.get(name, [])
        color = LEVEL_COLORS.get("À REVOIR", "#e67e22")
        head = (
            f'<div class="level-head" style="border-left:4px solid {color}">'
            f'<span class="level-dot" style="background:{color}"></span>'
            f'Outil : {html.escape(name)} '
            f'<span class="level-count">{len(items)}</span></div>'
        )
        if not items:
            sections.append(head + '<p class="muted">Aucun relevé pour cet outil.</p>')
            continue
        item_blocks = []
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ordered = sorted(items, key=lambda f: (order.get(f.severity, 4), f.file))
        for f in ordered:
            lv = level_for(f.severity)
            lcolor = LEVEL_COLORS.get(lv, "#64748b")
            loc = html.escape(f.file)
            rule = html.escape(f.rule_id)
            title = html.escape(f.title) or html.escape(f.rule_id)
            desc = html.escape(f.description)
            rec = html.escape(f.recommendation)
            snippet = html.escape(f.snippet)
            snip = f"<pre class='snip'>{snippet}</pre>" if snippet else ""
            # --- Bloc exploitation (comment un hacker exploite) ---
            expl_block = ""
            if f.exploitation:
                expl_block = (
                    f'<div class="item-expl" style="margin-top:6px;padding:8px 10px;'
                    f'background:rgba(239,68,68,.08);border-left:3px solid #ef4444;'
                    f'border-radius:4px;font-size:12.5px;color:#fca5a5;">'
                    f'<strong style="color:#ef4444;">🎯 Exploitation :</strong> '
                    f'{html.escape(f.exploitation)}</div>')
            # --- Bloc impact ---
            impact_block = ""
            if f.impact:
                impact_block = (
                    f'<div style="margin-top:4px;font-size:12px;color:#fbbf24;">'
                    f'<strong>⚡ Impact :</strong> {html.escape(f.impact)}</div>')
            # --- Bloc admin panel ---
            admin_block = ""
            if f.admin_panel:
                admin_block = (
                    f'<div style="margin-top:6px;padding:8px 10px;'
                    f'background:rgba(239,68,68,.15);border-left:3px solid #dc2626;'
                    f'border-radius:4px;font-size:13px;">'
                    f'<strong style="color:#fca5a5;">\U0001F513 Panneau admin trouv\u00e9 : '
                    f'<a href="{html.escape(f.admin_panel)}" target="_blank" '
                    f'style="color:#38bdf8;">{html.escape(f.admin_panel)}</a>'
                    f'</strong></div>')
            # --- Explication simple (comme un enfant de 5 ans) ---
            simple_block = ""
            simple = resolve_simple_explanation(f.rule_id, f.category, f.severity)
            if simple and simple.get("explanation"):
                simple_block = (
                    f'<div style="margin-top:8px;padding:10px 12px;'
                    f'background:rgba(56,189,248,.08);border-left:3px solid #38bdf8;'
                    f'border-radius:6px;font-size:13px;">'
                    f'<strong style="color:#38bdf8;">' 
                    f'{html.escape(simple.get("title", ""))}</strong><br>'
                    f'<span style="color:#94a3b8;">{html.escape(simple.get("explanation", ""))}</span>'
                    f'</div>')
            item_blocks.append(
                f'<div class="item" style="border-left:4px solid {lcolor}">'
                f'<div class="item-head">'
                f'<span class="rule-badge">{rule}</span>'
                f'<span class="item-title">{title}</span>'
                f'<span class="item-loc mono">{loc}</span>'
                f'{_badge(f.severity)}'
                f'</div>'
                f'{simple_block}'
                f'<div class="item-desc">{desc}</div>'
                f'{expl_block}'
                f'{impact_block}'
                f'{admin_block}'
                f'<div class="item-rec">Correction : {rec}</div>'
                f'{snip}'
                f'</div>'
            )
        sections.append(head + "".join(item_blocks))
    return "".join(sections)


def _exploit_section(findings) -> str:
    """Section dédiée aux résultats d'exploitation automatique."""
    exploit_findings = [f for f in findings if f.source and f.source.startswith("exploit-")]
    if not exploit_findings:
        return ""
    # Séparer les preuves trouvées vs les tests négatifs
    proven = [f for f in exploit_findings if f.severity == "critical"]
    tested = [f for f in exploit_findings if f.severity != "critical"]

    blocks = []
    # En-tête de la section
    blocks.append(
        '<div style="margin-top:30px;padding:20px 24px;background:linear-gradient(135deg,#1e1117,#0f0a14);'
        'border:2px solid #ef4444;border-radius:14px;">'
        '<h2 style="margin:0 0 6px;color:#fca5a5;font-size:20px;">'
        '🎯 Résultats de l\'exploitation automatique</h2>'
        '<p style="color:#94a3b8;margin:0 0 12px;font-size:13px;">'
        'Mode SAFE : aucune destruction, aucune modification, énumération uniquement. '
        'Les résultats ci-dessous prouvent que les failles sont réellement exploitable.</p>'
    )

    if proven:
        blocks.append(
            '<div style="padding:12px 16px;background:rgba(239,68,68,.15);'
            'border-left:4px solid #ef4444;border-radius:8px;margin-bottom:12px;">'
            f'<strong style="color:#ef4444;">⚠️ {len(proven)} faille(s) EXPLOITÉE(S) avec preuve :</strong>'
            '</div>'
        )
        for f in proven:
            snippet_escaped = html.escape(f.snippet[:500]) if f.snippet else ""
            # Détecter les commandes SQL dans le snippet
            sql_block = ""
            if "sqlmap" in f.source.lower() or "sql" in f.description.lower():
                sql_block = (
                    f'<div style="margin-top:8px;padding:10px 12px;'
                    f'background:rgba(139,92,246,.15);border-left:3px solid #8b5cf6;'
                    f'border-radius:6px;font-size:13px;">'
                    f'<strong style="color:#c4b5fd;">📋 Commandes SQL à exécuter :</strong><br>'
                    f'<code style="color:#a78bfa;font-family:monospace;font-size:12px;white-space:pre-wrap;">'
                    f'{snippet_escaped}</code></div>'
                )
            # Détecter les données extraites
            data_block = ""
            if "Bases de données" in f.title or "Tables" in f.title or "lignes" in f.title:
                data_block = (
                    f'<div style="margin-top:8px;padding:10px 12px;'
                    f'background:rgba(34,197,94,.1);border-left:3px solid #22c55e;'
                    f'border-radius:6px;font-size:13px;">'
                    f'<strong style="color:#86efac;">💾 Données extraites :</strong><br>'
                    f'<pre style="color:#86efac;font-family:monospace;font-size:12px;'
                    f'white-space:pre-wrap;margin:4px 0 0;">{snippet_escaped}</pre></div>'
                )
            # Détecter les credentials
            cred_block = ""
            if "login" in f.title.lower() or "password" in f.title.lower() or "credential" in f.title.lower():
                cred_block = (
                    f'<div style="margin-top:8px;padding:12px 16px;'
                    f'background:rgba(239,68,68,.2);border:2px solid #ef4444;'
                    f'border-radius:8px;font-size:14px;">'
                    f'<strong style="color:#fca5a5;">🔐 IDENTIFIANTS TROUVÉS :</strong><br>'
                    f'<code style="color:#fff;font-family:monospace;font-size:14px;'
                    f'font-weight:bold;">{snippet_escaped}</code></div>'
                )
            blocks.append(
                f'<div class="item" style="border-left:4px solid #ef4444;background:#1e1117;">'
                f'<div class="item-head">'
                f'<span class="rule-badge">{html.escape(f.rule_id)}</span>'
                f'<span class="item-title" style="color:#fca5a5;">{html.escape(f.title)}</span>'
                f'{_badge(f.severity)}'
                f'</div>'
                f'<div class="item-desc">{html.escape(f.description)}</div>'
                f'{cred_block}'
                f'{data_block}'
                f'{sql_block}'
                f'<div class="item-expl" style="margin-top:6px;padding:8px 10px;'
                f'background:rgba(239,68,68,.1);border-left:3px solid #ef4444;'
                f'border-radius:4px;font-size:12.5px;color:#fca5a5;">'
                f'<strong style="color:#ef4444;">🎯 Preuve d\'exploitation :</strong> '
                f'{snippet_escaped}</div>'
                f'</div>'
            )

    if tested:
        blocks.append(
            f'<div style="padding:10px 16px;background:rgba(34,197,94,.08);'
            f'border-left:4px solid #22c55e;border-radius:8px;margin-top:16px;margin-bottom:8px;">'
            f'<strong style="color:#22c55e;">✅ {len(tested)} test(s) non exploitable</strong>'
            f' <span style="color:#94a3b8;font-size:12px;">(faille détectée mais non exploitable en mode safe)</span>'
            f'</div>'
        )
        for f in tested:
            blocks.append(
                f'<div class="item" style="border-left:4px solid #22c55e;opacity:0.7;">'
                f'<div class="item-head">'
                f'<span class="rule-badge">{html.escape(f.rule_id)}</span>'
                f'<span class="item-title">{html.escape(f.title)}</span>'
                f'{_badge(f.severity)}'
                f'</div>'
                f'<div class="item-desc">{html.escape(f.description)}</div>'
                f'</div>'
            )

    blocks.append('</div>')
    return "\n".join(blocks)


def generate_web_html(findings, stats, by_tool: dict, target_url: str,
                      meta: dict, preflight: dict, score: dict = None) -> str:
    """Construit la page HTML complète du rapport web."""
    now = meta.get("timestamp", datetime.now().isoformat(timespec="seconds"))
    hero = _hero_block(score) if score else ""
    cards = _summary_cards(stats, score, by_tool) if score else ""
    tool_table = _tool_table(by_tool)
    preflight_table = _preflight_table(preflight)
    sections = _tool_sections(findings, by_tool)
    exploit_section = _exploit_section(findings)

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IRON MAN AI — Audit Kali</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    margin: 0; padding: 24px; background: #0f172a; color: #e2e8f0;
    print-color-adjust: exact; -webkit-print-color-adjust: exact;
  }}
  .wrap {{ max-width: 1080px; margin: 0 auto; }}
  header {{ display:flex; align-items:baseline; justify-content:space-between;
           flex-wrap:wrap; gap:8px; border-bottom:1px solid #334155; padding-bottom:16px; }}
  h1 {{ margin:0; font-size:26px; letter-spacing:.5px; }}
  h1 .accent {{ color:#38bdf8; }}
  .meta {{ color:#94a3b8; font-size:13px; }}
  .meta code {{ background:#1e293b; padding:2px 6px; border-radius:4px; }}
  .badge-ai {{ background:#10b981; color:#022c22; border-radius:12px; padding:2px 10px;
              font-size:11px; font-weight:600; letter-spacing:.4px; }}
  .hero {{ display:flex; gap:28px; align-items:center; margin:22px 0 6px;
           padding:22px 26px; background:linear-gradient(135deg,#1e293b,#0f172a);
           border:1px solid #334155; border-radius:14px; }}
  .hero-score {{ font-size:64px; font-weight:800; line-height:1; }}
  .score-num {{ color:#f8fafc; }}
  .score-total {{ font-size:22px; color:#94a3b8; font-weight:600; }}
  .hero-right {{ flex:1; }}
  .hero-grade {{ font-size:64px; font-weight:800; line-height:1; }}
  .hero-bar {{ height:12px; background:#334155; border-radius:6px; margin:12px 0 6px; }}
  .hero-fill {{ height:100%; border-radius:6px; }}
  .hero-sub {{ color:#94a3b8; font-size:13px; }}
  .cards {{ display:flex; gap:12px; margin:18px 0; flex-wrap:wrap; }}
  .card {{ flex:1; min-width:110px; background:#1e293b; border-radius:10px;
          padding:14px; text-align:center; }}
  .card-num {{ font-size:30px; font-weight:700; }}
  .card-label {{ color:#94a3b8; text-transform:uppercase; font-size:12px; }}
  h2 {{ font-size:18px; margin:30px 0 10px; color:#f8fafc;
        border-bottom:1px solid #334155; padding-bottom:6px; }}
  .tooltable {{ width:100%; border-collapse:collapse; margin:10px 0; }}
  .tooltable th, .tooltable td {{ padding:8px 10px; text-align:left;
    border-bottom:1px solid #1e293b; }}
  .tooltable th {{ color:#94a3b8; font-weight:600; font-size:12px;
    text-transform:uppercase; }}
  .level-head {{ display:flex; align-items:center; gap:8px; font-weight:700;
                 font-size:15px; margin:18px 0 8px; padding-left:10px; }}
  .level-dot {{ width:10px; height:10px; border-radius:50%; display:inline-block; }}
  .level-count {{ background:#1e293b; border-radius:20px; padding:1px 8px;
                  font-size:12px; color:#94a3b8; }}
  .item {{ background:#1e293b; border-radius:8px; padding:12px 14px; margin:8px 0; }}
  .item-head {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
  .rule-badge {{ font-family:monospace; font-size:11px; background:#0f172a;
                 padding:2px 8px; border-radius:4px; color:#c4b5fd;
                 word-break:break-all; }}
  .item-title {{ font-weight:600; flex:1; min-width:180px; }}
  .item-loc {{ font-size:12.5px; color:#7dd3fc; }}
  .item-desc {{ margin-top:6px; color:#cbd5e1; font-size:13px; }}
  .item-rec {{ margin-top:4px; color:#86efac; font-size:12.5px; }}
  .snip {{ margin:8px 0 0; padding:6px 10px; background:#0f172a;
          border-left:3px solid #475569; border-radius:4px;
          font-family:monospace; font-size:12px; overflow-x:auto; color:#e2e8f0; }}
  .mono {{ font-family:'Cascadia Code',Consolas,monospace; }}
  .muted {{ color:#64748b; }}
  .num {{ text-align:center; }}
  .badge {{ color:#fff; border-radius:20px; padding:2px 10px; font-size:11px;
           text-transform:uppercase; letter-spacing:.4px; white-space:nowrap; }}
  footer {{ margin-top:34px; color:#64748b; font-size:12px; text-align:center; }}

  @media (prefers-color-scheme: light) {{
    body {{ background:#f1f5f9; color:#1e293b; }}
    header {{ border-color:#e2e8f0; }}
    .hero {{ background:linear-gradient(135deg,#ffffff,#f8fafc); border-color:#e2e8f0; }}
    .hero-score .score-num {{ color:#0f172a; }}
    .card, .item, .tooltable td, .level-count {{ background:#fff; }}
    .rule-badge {{ background:#f1f5f9; color:#6d28d9; }}
    .snip {{ background:#f8fafc; border-left-color:#cbd5e1; }}
    .item-desc {{ color:#475569; }}
    .meta {{ color:#64748b; }}
  }}

  @media print {{
    @page {{ size: A4; margin: 12mm; }}
    body {{ background:#fff !important; color:#111 !important; padding:0; }}
    header {{ border-bottom:1px solid #ddd; }}
    .hero, .card, .item, .tooltable tr {{ break-inside: avoid; }}
    .hero {{ background:#f8fafc !important; border:1px solid #ddd; }}
    .item {{ background:#fff !important; border-left-width:4px !important; }}
    .no-print {{ display: none !important; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>IRON&nbsp;MAN&nbsp;<span class="accent">AI</span> — Audit <span class="accent">Kali</span></h1>
    <div class="meta">
      <span class="badge-ai">Sans IA</span>&nbsp;
      Cible&nbsp;: <code>{html.escape(target_url)}</code> ·
      {meta.get('tool', 'IRON MAN AI')} v{meta.get('version', '')} ·
      {html.escape(now)}
    </div>
  </header>

  {hero}
  {cards}

  <h2>Résultats par outil</h2>
  {tool_table}

  <h2>Préflight (présence des outils)</h2>
  {preflight_table}

  <h2>Détail des relevés ({stats.get('total_findings', 0)})</h2>
  {sections}

  {exploit_section}

  <footer>Généré par <strong>IRON MAN AI</strong> — Audit Kali. Ne tester que des cibles
  que vous possédez ou êtes autorisé à tester.</footer>
</div>
</body>
</html>
"""


def write_web_html(findings, stats, by_tool: dict, target_url: str,
                   meta: dict, preflight: dict, output_path: str,
                   score: dict = None) -> None:
    """Écrit le rapport web HTML sur `output_path`."""
    page = generate_web_html(findings, stats, by_tool, target_url, meta,
                             preflight, score)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(page)
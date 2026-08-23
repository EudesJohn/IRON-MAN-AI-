"""Rapport HTML enrichi de CodeScan (parité de structure avec Herald).

Génère une page HTML autonome (CSS embarqué, aucun accès réseau) qui
reproduit la structure du rapport de référence :
  - bandeau de synthèse avec cible/date/badge « Sans IA » ;
  - **hero score** : note /100 + lettre de grade colorée + barre de
    progression ;
  - cartes de synthèse (Relevés, Critiques, Fichiers, Sécurité, Qualité,
    Performance) ;
  - findings regroupés par niveau lisible (CRITIQUE → À REVOIR → MINEUR),
    chaque entrée affichant id de règle, titre avec valeur + seuil,
    fichier:ligne, description, recommandation et extrait de code ;
  - répartition par catégorie (barres) ;
  - styles d'impression : `@media print` au format A4 sans coupes.

Le rapport reste imprimable en PDF directement depuis le navigateur (le
`@media print` découpe proprement les pages A4).
"""

import html
from kali.exploits import resolve_simple_explanation
from datetime import datetime

from scanner.models import LEVEL_ORDER, level_for

# Couleurs associées à chaque sévérité.
SEV_COLORS = {
    "critical": "#c0392b",   # rouge foncé
    "high":     "#e67e22",   # orange
    "medium":   "#f1c40f",   # jaune
    "low":      "#3498db",   # bleu
}

# Couleurs des niveaux lisibles du rapport.
LEVEL_COLORS = {
    "CRITIQUE": "#c0392b",
    "À REVOIR": "#e67e22",
    "MINEUR":   "#27ae60",
}

# Couleurs par lettre de grade (A → F).
GRADE_COLORS = {
    "A": "#2ecc71", "B": "#3498db", "C": "#f1c40f",
    "D": "#e67e22", "F": "#e74c3c",
}

# Libellés français des catégories (répartition + titres).
CATEGORY_LABELS = {
    "injection": "Injection (SQL / commande)",
    "secrets": "Secrets exposés",
    "xss": "Cross-Site Scripting (XSS)",
    "code_quality": "Qualité de code",
    "performance": "Performance / asynchrone",
    "security_misc": "Sécurité diverse",
    "dependencies": "Dépendances (CVE)",
}


def _badge(severity: str) -> str:
    """Badge coloré d'une sévérité."""
    color = SEV_COLORS.get(severity, "#95a5a6")
    return (f'<span class="badge" style="background:{color}">'
            f'{html.escape(severity)}</span>')


def _hero_block(score: dict) -> str:
    """Bloc « hero » de la note /100 (avec barre de progression)."""
    sc = score.get("score", 0)
    grade = score.get("grade", "F")
    color = GRADE_COLORS.get(grade, "#95a5a6")
    total = score.get("total_findings", 0)
    crit = score.get("by_level", {}).get("CRITIQUE", 0)
    files = score.get("files_scanned", 0)
    return f"""
    <div class="hero">
      <div class="hero-left">
        <div class="hero-score"><span class="score-num">{sc}</span>
          <span class="score-total">/100</span></div>
      </div>
      <div class="hero-right">
        <div class="hero-grade" style="color:{color};border-color:{color}">{grade}</div>
        <div class="hero-label">Note de qualité</div>
        <div class="hero-bar"><div class="hero-fill"
             style="width:{sc}%;background:{color}"></div></div>
        <div class="hero-sub">{total} relevés · {crit} critique(s) · {files} fichiers</div>
      </div>
    </div>"""


def _summary_cards(stats: dict, score: dict) -> str:
    """Cartes de synthèse du rapport (relevés, critiques, fichiers, domaines)."""
    by_level = score.get("by_level", {})
    cards = [
        ("Relevés", score.get("total_findings", 0), "#38bdf8"),
        ("Critiques", by_level.get("CRITIQUE", 0), "#c0392b"),
        ("À revoir", by_level.get("À REVOIR", 0), "#e67e22"),
        ("Fichiers", stats.get("files_scanned", 0), "#94a3b8"),
        ("Sécurité", score.get("security", 0), "#e74c3c"),
        ("Qualité", score.get("quality", 0), "#38bdf8"),
        ("Performance", score.get("performance", 0), "#a855f7"),
    ]
    out = []
    for label, num, color in cards:
        out.append(
            f'<div class="card" style="border-top:4px solid {color}">'
            f'<div class="card-num">{num}</div>'
            f'<div class="card-label">{label}</div></div>'
        )
    return f'<div class="cards">{"".join(out)}</div>'


def _category_table(stats: dict) -> str:
    """Répartition des findings par catégorie (barres proportionnelles)."""
    by_cat = stats.get("by_category", {})
    if not by_cat:
        return '<p class="muted">Aucun résultat.</p>'
    total = sum(by_cat.values())
    rows = []
    for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        label = CATEGORY_LABELS.get(cat, cat)
        width = round(100 * n / total)
        rows.append(
            f"<tr><td>{html.escape(label)}</td>"
            f"<td class='num'>{n}</td>"
            f"<td class='bar-cell'><div class='bar' style='width:{width}%'></div></td>"
            f"</tr>"
        )
    return "<table class='cats'>" + "".join(rows) + "</table>"


def _level_items(findings, level: str) -> str:
    """Bloc des findings d'un niveau lisible (parité Herald)."""
    color = LEVEL_COLORS.get(level, "#64748b")
    if not findings:
        return f'<div class="level-head" style="border-color:{color}">' \
               f'<span class="level-dot" style="background:{color}"></span>' \
               f'{level} <span class="level-count">0</span></div>' \
               f'<p class="muted">Aucun relevé de ce niveau.</p>'

    # Tri : sévérité la plus grave d'abord, puis fichier/ligne.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered = sorted(findings, key=lambda f: (order.get(f.severity, 4),
                                              f.file, f.line))

    head = (
        f'<div class="level-head" style="border-left:4px solid {color}">'
        f'<span class="level-dot" style="background:{color}"></span>'
        f'{level} <span class="level-count">{len(ordered)}</span></div>'
    )
    items = []
    for f in ordered:
        loc = html.escape(f.file)
        if f.line:
            loc += f":{f.line}"
        rule = html.escape(f.rule_id)
        title = html.escape(f.title) or html.escape(f.rule_id)
        desc = html.escape(f.description)
        rec = html.escape(f.recommendation)
        snippet = html.escape(f.snippet)
        snip = f"<pre class='snip'>{snippet}</pre>" if snippet else ""
        cve = (f" <span class='cve'>{html.escape(f.cve)}</span>"
               if f.cve else "")
        # --- Bloc exploitation ---
        expl_block = ""
        if f.exploitation:
            expl_block = (
                f'<div style="margin-top:6px;padding:8px 10px;'
                f'background:rgba(239,68,68,.08);border-left:3px solid #ef4444;'
                f'border-radius:4px;font-size:12.5px;color:#fca5a5;">'
                f'<strong style="color:#ef4444;">Exploitation :</strong> '
                f'{html.escape(f.exploitation)}</div>')
        impact_block = ""
        if f.impact:
            impact_block = (
                f'<div style="margin-top:4px;font-size:12px;color:#fbbf24;">'
                f'<strong>Impact :</strong> {html.escape(f.impact)}</div>')
        admin_block = ""
        if f.admin_panel:
            admin_block = (
                f'<div style="margin-top:6px;padding:8px 10px;'
                f'background:rgba(239,68,68,.15);border-left:3px solid #dc2626;'
                f'border-radius:4px;font-size:13px;">'
                f'<strong style="color:#fca5a5;">Panneau admin : '
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
        items.append(
            f'<div class="item" style="border-left:4px solid {color}">'
            f'<div class="item-head">'
            f'<span class="rule-badge">{rule}</span>'
            f'<span class="item-title">{title}{cve}</span>'
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
    return head + "".join(items)


def _findings_by_level(findings, score: dict) -> str:
    """Sections du rapport groupées par niveau lisible (CRITIQUE → …).
    Les niveaux sont toujours affichés dans l'ordre du rapport, y compris
    vides (parité Herald)."""
    groups = {lv: [] for lv in LEVEL_ORDER}
    for f in findings:
        groups[level_for(f.severity)].append(f)
    return "".join(
        _level_items(groups[lv], lv) for lv in LEVEL_ORDER
    )


def generate_html(findings, stats, target, meta: dict, score: dict = None) -> str:
    """Construit la page HTML complète et la renvoie sous forme de chaîne."""
    total = stats.get("total_findings", len(findings))
    scanned = stats.get("files_scanned", 0)
    now = meta.get("timestamp", datetime.now().isoformat(timespec="seconds"))
    hero = _hero_block(score) if score else ""
    cards = _summary_cards(stats, score) if score else ""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeScan — Rapport d'analyse</title>
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

  /* Hero score */
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
  .cve {{ font-size:11px; color:#fbbf24; }}

  .cats {{ width:100%; border-collapse:collapse; }}
  .cats td {{ padding:8px 10px; }}
  .cats tr {{ background:#1e293b; }}
  .cats tr:nth-child(even) {{ background:#16213a; }}
  .bar-cell {{ width:40%; }}
  .bar {{ height:10px; background:#38bdf8; border-radius:5px; min-width:2px; }}
  .num {{ text-align:center; }}
  .mono {{ font-family:'Cascadia Code',Consolas,monospace; }}
  .muted {{ color:#64748b; }}
  .badge {{ color:#fff; border-radius:20px; padding:2px 10px; font-size:11px;
           text-transform:uppercase; letter-spacing:.4px; white-space:nowrap; }}
  footer {{ margin-top:34px; color:#64748b; font-size:12px; text-align:center; }}

  @media (prefers-color-scheme: light) {{
    body {{ background:#f1f5f9; color:#1e293b; }}
    header {{ border-color:#e2e8f0; }}
    .hero {{ background:linear-gradient(135deg,#ffffff,#f8fafc); border-color:#e2e8f0; }}
    .hero-score .score-num {{ color:#0f172a; }}
    .card, .item, .cats tr, .level-count {{ background:#fff; }}
    .cats tr:nth-child(even) {{ background:#f8fafc; }}
    .rule-badge {{ background:#f1f5f9; color:#6d28d9; }}
    .snip {{ background:#f8fafc; border-left-color:#cbd5e1; }}
    .item-desc {{ color:#475569; }}
    .meta {{ color:#64748b; }}
  }}

  @media print {{
    @page {{ size: A4; margin: 12mm; }}
    body {{ background:#fff !important; color:#111 !important; padding:0; }}
    header {{ border-bottom:1px solid #ddd; }}
    .hero, .card, .item, .cats tr {{ break-inside: avoid; }}
    .hero {{ background:#f8fafc !important; border:1px solid #ddd; }}
    .item {{ background:#fff !important; border-left-width:4px !important; }}
    .no-print {{ display: none !important; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Code<span class="accent">Scan</span> — Rapport d'analyse</h1>
    <div class="meta">
      <span class="badge-ai">Sans IA</span>&nbsp;
      Cible&nbsp;: <code>{html.escape(target)}</code> ·
      {meta.get('tool', 'CodeScan')} v{meta.get('version', '')} ·
      {html.escape(now)}
    </div>
  </header>

  {hero}
  {cards}

  <h2>Répartition par catégorie</h2>
  {_category_table(stats)}

  <h2>Détail des relevés ({total})</h2>
  {_findings_by_level(findings, score)}

  <footer>Généré par CodeScan — analyse statique sans API d'IA.
  Vérifier chaque résultat avant de le corriger.</footer>
</div>
</body>
</html>
"""


def write_html_report(findings, stats, target, meta: dict, output_path: str,
                      score: dict = None) -> None:
    """Écrit le rapport HTML sur `output_path`.

    `score` (optionnel) : la note /100 et son grade sont affichés dans le
    bandeau de synthèse (haut du rapport).
    """
    page = generate_html(findings, stats, target, meta, score)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(page)
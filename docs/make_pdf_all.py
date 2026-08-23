"""Génère le PDF regroupant TOUS les manuels IRON MAN AI en un seul.

Couverture + table des matières + chaque manuel avec un saut de page.
Réutilise le pipeline de make_pdf (markdown -> HTML autonome -> PDF
Chromium/wkhtmltopdf), donc aucune dépendance supplémentaire.

Usage :
    python docs/make_pdf_all.py [out.pdf] [--css manuel.css]
"""

import argparse
import os
import re
import sys

from make_to_html import build_document
from make_pdf import find_browser, find_wkhtmltopdf, pdf_with_browser, \
    pdf_with_wkhtmltopdf

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(DOCS_DIR)

# Ordre des manuels : (titre court, chemin relatif au projet)
MANUALS = [
    ("CodeScan — Analyse statique de code", "MANUEL.md"),
    ("IRON MAN AI — Audit web (Kali)", "docs/MANUEL_KALI.md"),
    ("IRON MAN AI — Guide Windows", "docs/MANUEL_WINDOWS.md"),
    ("IRON MAN AI — Pentest WiFi", "docs/MANUEL_WIFI.md"),
    ("IRON MAN AI — Analyse Android (APK)", "docs/MANUEL_ANDROID.md"),
    ("IRON MAN AI — Audit de périphérique", "docs/MANUEL_DEVICE.md"),
    ("IRON MAN AI — Contrôler votre téléphone", "docs/MANUEL_CONTROLE.md"),
]

# Bundles « manuel complet » par plateforme :
#   Kali    = tout sauf le guide Windows (spécifique à Windows)
#   Windows = tout sauf le guide Kali (spécifique aux outils Kali)
KALI_MANUALS = [m for m in MANUALS if m[1] != "docs/MANUEL_WINDOWS.md"]
WINDOWS_MANUALS = [m for m in MANUALS if m[1] != "docs/MANUEL_KALI.md"]

BUNDLES = {
    "kali": (KALI_MANUALS, "MANUEL_COMPLET_KALI.pdf",
             "IRON MAN AI — Manuel complet (Kali)"),
    "windows": (WINDOWS_MANUALS, "MANUEL_COMPLET_WINDOWS.pdf",
                "IRON MAN AI — Manuel complet (Windows)"),
}

COVER_CSS = """
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }}
.cover {{ text-align: center; padding: 120px 40px; }}
.cover h1 {{ font-size: 42px; color: #00d4ff;
             border: none; margin-bottom: 8px; }}
.cover .sub {{ font-size: 20px; color: #888; margin-bottom: 60px; }}
.cover .toc {{ text-align: left; max-width: 640px; margin: 0 auto; }}
.cover .toc div {{ padding: 10px 0; border-bottom: 1px solid #2a2a4a;
                   font-size: 17px; }}
.cover .toc .n {{ color: #00d4ff; font-weight: bold; margin-right: 12px; }}
.cover .foot {{ margin-top: 80px; color: #555; font-size: 14px; }}
.section {{ break-before: page; }}
"""


def _first_h1(md: str) -> str:
    """Extrait le premier titre H1 du markdown."""
    for line in md.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def _extract_doc(html: str) -> str:
    """Extrait le contenu de <div class=\"doc\">…</div> d'une page rendue."""
    m = re.search(r'<div class="doc">(.*?)</div>', html, re.S)
    return m.group(1) if m else html


def build_combined_html(css: str = None, manuals: list = None,
                        title: str = None) -> str:
    """Assemble la page unique (couverture + sommaire + manuels).

    `manuals` : liste (titre, chemin) à inclure (défaut : tous) ;
    `title`   : titre de la couverture (défaut : « Manuel complet »).
    """
    if css is None:
        css = os.path.join(DOCS_DIR, "manuel.css")
    with open(css, "r", encoding="utf-8") as fh:
        css_content = fh.read()

    if manuals is None:
        manuals = MANUALS
    if title is None:
        title = "IRON MAN AI — Manuel complet"

    # Couverture + sommaire
    toc_html = "".join(
        f'<div><span class="n">{i + 1}.</span>{t}</div>'
        for i, (t, _) in enumerate(manuals)
    )
    cover = f"""<div class="cover">
<h1>{title}</h1>
<div class="sub">Audit web · WiFi · Android · Périphériques · CodeScan</div>
<div class="toc">{toc_html}</div>
<div class="foot">Généré automatiquement — cadre d'utilisation autorisé
uniquement (--authorized).</div>
</div>"""

    # Chaque manuel, converti puis inséré avec un saut de page
    sections = []
    for title, rel in manuals:
        path = os.path.join(PROJECT_ROOT, rel)
        with open(path, "r", encoding="utf-8") as fh:
            md = fh.read()
        page = build_document(md, title, css)
        body = _extract_doc(page)
        sections.append(f'<div class="section">{body}</div>')

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>IRON MAN AI — Manuel complet</title>
<style>
{css_content}
{COVER_CSS}
</style>
</head>
<body class="print">
<div class="doc">
{cover}
{''.join(sections)}
</div>
</body>
</html>"""
    return html


def make_pdf_all(out_pdf: str, css: str = None, manuals: list = None,
                 title: str = None) -> int:
    """Génère le PDF combiné. Retourne le code de sortie."""
    html = build_combined_html(css, manuals=manuals, title=title)
    return make_pdf_all_html(html, out_pdf)


def make_pdf_all_html(html: str, out_pdf: str) -> int:
    out_pdf = os.path.abspath(out_pdf)
    base = os.path.splitext(out_pdf)[0]
    html_path = base + ".html"

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[make_pdf_all] HTML généré : {html_path}")

    browser = find_browser()
    if browser:
        print(f"[make_pdf_all] navigateur détecté : {os.path.basename(browser)}")
        if pdf_with_browser(browser, html_path, out_pdf):
            print(f"[make_pdf_all] PDF écrit : {out_pdf}")
            return 0

    wk = find_wkhtmltopdf()
    if wk and pdf_with_wkhtmltopdf(html_path, out_pdf):
        print(f"[make_pdf_all] PDF écrit : {out_pdf}")
        return 0

    print("[make_pdf_all] Aucun moteur PDF détecté (Chrome/Edge/Chromium ou "
          "wkhtmltopdf).")
    print("[make_pdf_all] Ouvrez le HTML généré dans un navigateur puis "
          "Imprimer -> Enregistrer en PDF.")
    return 1


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(
        description="Génère le(s) PDF complet(s) des manuels IRON MAN AI "
                    "(tous, Kali ou Windows).")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--kali", action="store_true",
                       help="Manuel complet Kali (tout sauf le guide Windows).")
    group.add_argument("--windows", action="store_true",
                       help="Manuel complet Windows (tout sauf le guide Kali).")
    ap.add_argument("out", nargs="?",
                    help="Fichier PDF de sortie (défaut : MANUEL_COMPLET.pdf).")
    ap.add_argument("--css", default=os.path.join(DOCS_DIR, "manuel.css"))
    args = ap.parse_args(argv)

    if args.kali:
        manuals, fname, title = BUNDLES["kali"]
        return make_pdf_all(os.path.join(DOCS_DIR, fname), args.css,
                            manuals=manuals, title=title)
    if args.windows:
        manuals, fname, title = BUNDLES["windows"]
        return make_pdf_all(os.path.join(DOCS_DIR, fname), args.css,
                            manuals=manuals, title=title)
    out = args.out or os.path.join(DOCS_DIR, "MANUEL_COMPLET.pdf")
    return make_pdf_all(out, args.css)


if __name__ == "__main__":
    raise SystemExit(main())

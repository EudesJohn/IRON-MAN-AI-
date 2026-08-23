"""Assistant de génération de PDF pour les manuels CodeScan.

Pipeline (le plus « Les deux » possible) :
  1. convertit le Markdown en HTML autonome via make_to_html (stdlib) ;
  2. cherche un navigateur Chromium-compatible (chrome, chromium,
     microsoft-edge, google-chrome) et utilise `--headless --print-to-pdf` ;
  3. sinon essaie wkhtmltopdf ;
  4. sinon affiche les instructions « Imprimer en PDF » depuis le navigateur.

Aucune dépendance externe n'est requise pour produire le HTML ; le PDF
est créé si un navigateur est disponible, sinon des instructions claires
sont données. Un script optionnel (fpdf2) permet aussi un PDF sans
navigateur — voir make_pdf_fpdf2.py.
"""

import argparse
import os
import shutil
import subprocess
import sys

from make_to_html import build_document


# Binaires navigateur (première correspondance trouvée via shutil.which).
_BROWSERS = [
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "microsoft-edge", "msedge", "chrome",
]


def find_browser() -> str:
    """Renvoie le chemin d'un navigateur Chromium-compatible, ou None."""
    for name in _BROWSERS:
        path = shutil.which(name)
        if path:
            return path
    # Chemins Windows usuels (si shutil.which n'aboutit pas).
    candidates = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def find_wkhtmltopdf() -> str:
    """Renvoie le chemin de wkhtmltopdf, ou None."""
    return shutil.which("wkhtmltopdf")


def pdf_with_browser(browser: str, html_path: str, pdf_path: str) -> bool:
    """Génère le PDF via --headless --print-to-pdf. Renvoie True si réussi.

    Tente plusieurs variantes de drapeaux headless (--headless puis
    --headless=new) : certaines versions d'Edge/Chrome exigent une forme
    spécifique pour --print-to-pdf.
    """
    file_url = "file:///" + os.path.abspath(html_path).replace("\\", "/")
    variants = [
        ["--headless", "--disable-gpu", "--no-sandbox",
         "--disable-dev-shm-usage"],
        ["--headless=new", "--disable-gpu", "--no-sandbox"],
        ["--headless", "--disable-gpu"],
    ]
    for flags in variants:
        cmd = [browser] + flags + [f"--print-to-pdf={pdf_path}", file_url]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and os.path.isfile(pdf_path) and \
                os.path.getsize(pdf_path) > 0:
            return True
    return False


def pdf_with_wkhtmltopdf(html_path: str, pdf_path: str) -> bool:
    """Génère le PDF via wkhtmltopdf si présent. Renvoie True si réussi."""
    cmd = ["wkhtmltopdf", "--enable-local-file-access", html_path, pdf_path]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=180)
        return result.returncode == 0 and os.path.isfile(pdf_path) and \
            os.path.getsize(pdf_path) > 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def make_pdf(md_path: str, out_pdf: str, css: str = None) -> int:
    """Génère le PDF pour le manuel `md_path`. Renvoie le code de sortie."""
    # Chemins absolus : les moteurs headless (Chrome/Edge) acceptent mal les
    # chemins relatifs pour --print-to-pdf et file:///.
    out_pdf = os.path.abspath(out_pdf)
    base = os.path.splitext(out_pdf)[0]
    html_path = base + ".html"

    with open(md_path, "r", encoding="utf-8") as fh:
        md = fh.read()
    title = os.path.basename(md_path).replace(".md", "").replace("_", " ")
    page = build_document(md, title, css)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"[make_pdf] HTML généré : {html_path}")

    browser = find_browser()
    if browser:
        print(f"[make_pdf] navigateur détecté : {os.path.basename(browser)}")
        if pdf_with_browser(browser, html_path, out_pdf):
            print(f"[make_pdf] PDF écrit : {out_pdf}")
            return 0
        print("[make_pdf] échec du rendu headless, on tente wkhtmltopdf…")

    wk = find_wkhtmltopdf()
    if wk:
        print(f"[make_pdf] wkhtmltopdf détecté : {wk}")
        if pdf_with_wkhtmltopdf(html_path, out_pdf):
            print(f"[make_pdf] PDF écrit : {out_pdf}")
            return 0

    print("[make_pdf] Aucun moteur PDF détecté (Chrome/Edge/Chromium ou "
          "wkhtmltopdf).")
    print("[make_pdf] Solution : ouvrez le HTML généré dans un navigateur puis "
          "utilisez Imprimer -> Enregistrer en PDF.")
    print("[make_pdf] (ou : pip install fpdf2 puis python docs/make_pdf_fpdf2.py "
          f"{md_path} {out_pdf})")
    return 1


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(
        description="Génère le PDF d'un manuel CodeScan (markdown -> html -> pdf).")
    ap.add_argument("md", metavar="FICHIER.md")
    ap.add_argument("out", metavar="FICHIER.pdf")
    ap.add_argument("--css", default=os.path.join(os.path.dirname(__file__),
                                                  "manuel.css"),
                    help="Feuille CSS à embarquer (défaut : manuel.css).")
    args = ap.parse_args(argv)
    return make_pdf(args.md, args.out, args.css)


if __name__ == "__main__":
    sys.exit(main())
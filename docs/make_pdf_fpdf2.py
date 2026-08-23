"""Script optionnel : génère un PDF directement (sans navigateur) via fpdf2.

Requiert `pip install fpdf2`. N'est PAS une dépendance du projet : c'est un
raccourci facultatif pour obtenir un PDF sans avoir Chrome/Edge/Chromium ni
wkhtmltopdf. La mise en page est volontairement simple (titres, paragraphes,
puces, code en retrait) — pour un rendu soigné, préférez make_pdf.py.

Usage :
    python docs/make_pdf_fpdf2.py MANUEL_KALI.md sortie.pdf
"""

import os
import sys


def _line_width(text: str, font_size: int) -> float:
    """Estimation grossière de la largeur en mm (utile aux retours à la ligne)."""
    return len(text) * font_size * 0.55


def md_to_fpdf_text(md_path: str):
    """Lit le markdown et le découpe en segments (style, texte)."""
    segments = []  # (style, texte) ; style in {"h1","h2","h3","li","code","p"}
    with open(md_path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    in_code = False
    for line in lines:
        s = line.rstrip()
        if s.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            segments.append(("code", s))
            continue
        stripped = s.strip()
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            style = f"h{min(level, 3)}"
            segments.append((style, stripped.lstrip("# ").strip()))
        elif stripped.startswith("- ") or stripped.startswith("* "):
            segments.append(("li", stripped[2:].strip()))
        elif stripped.isdigit() or re_ol(stripped):
            segments.append(("li", stripped))
        elif stripped:
            segments.append(("p", stripped))
    return segments


def re_ol(text: str) -> bool:
    return len(text) > 2 and text[0].isdigit() and text[1] in ".)"


def build_pdf(md_path: str, out_pdf: str) -> int:
    """Construit le PDF via fpdf2. Renvoie 0 si réussi, 1 sinon."""
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        print("[fpdf2] fpdf2 n'est pas installé : `pip install fpdf2`.",
              file=sys.stderr)
        return 1

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)
    # Police core latin-1 (aucune dépendance de police requise) : couvre
    # les accents français usuels.
    pdf.set_font("helvetica", "B", 18)
    title = os.path.basename(md_path).replace(".md", "").replace("_", " ")
    pdf.cell(0, 10, title.encode("latin-1", "replace").decode("latin-1"),
             new_x="LMARGIN", new_y="NEXT")

    for style, text in md_to_fpdf_text(md_path):
        text_latin = text.encode("latin-1", "replace").decode("latin-1")
        if style == "h1":
            pdf.set_font("helvetica", "B", 15)
            pdf.ln(3)
            pdf.cell(0, 8, text_latin, new_x="LMARGIN", new_y="NEXT")
        elif style == "h2":
            pdf.set_font("helvetica", "B", 13)
            pdf.ln(2)
            pdf.cell(0, 7, text_latin, new_x="LMARGIN", new_y="NEXT")
        elif style == "h3":
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 6, text_latin, new_x="LMARGIN", new_y="NEXT")
        elif style == "li":
            pdf.set_font("helvetica", "", 10)
            pdf.cell(0, 6, "- " + text_latin, new_x="LMARGIN", new_y="NEXT")
        elif style == "code":
            pdf.set_font("courier", "", 8)
            pdf.cell(0, 5, "    " + text_latin, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 6, text_latin)

    pdf.output(out_pdf)
    if os.path.isfile(out_pdf) and os.path.getsize(out_pdf) > 0:
        print(f"[fpdf2] PDF écrit : {out_pdf}")
        return 0
    print(f"[fpdf2] Échec de l'écriture : {out_pdf}", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    if len(sys.argv if argv is None else argv) < 3:
        print("Usage : python docs/make_pdf_fpdf2.py FICHIER.md FICHIER.pdf")
        return 2
    md, out = (argv if argv is not None else sys.argv[1:3])
    return build_pdf(md, out)


if __name__ == "__main__":
    sys.exit(main())
"""Mini convertisseur Markdown → HTML autonome (stdlib uniquement).

Suffisamment riche pour les manuels CodeScan : titres (h1-h4), listes à
puces, listes numérotées, code en ligne et blocs de code, tableaux
markdown simples, paragraphes et emphase légère. Produit une page HTML
autonome (CSS externe facultatif) prête à imprimer.

Usage :
    python docs/make_to_html.py MANUEL_KALI.md out.html [--css manuel.css]
"""

import argparse
import html as html_mod
import os
import re
import sys


def _esc(text: str) -> str:
    return html_mod.escape(text, quote=False)


def _inline(text: str) -> str:
    """Formatage léger des lignes : code `...`, gras **...**.

    Échappe d'abord le texte entier (les `<`, `>`, `&` d'un manuel ne doivent
    jamais devenir du HTML brut) puis applique le formatage sur le texte déjà
    échappé (le contenu des spans n'est pas ré-échappé).
    """
    text = _esc(text)
    text = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*",
                  lambda m: f"<strong>{m.group(1)}</strong>", text)
    return text


def _split_row(line: str) -> list:
    """Découpe une ligne de tableau markdown en cellules."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _join_continued_item(lines: list, i: int, first_text: str) -> tuple:
    """Lit un élément de liste et ses lignes de continuation.

    Une ligne de continuation est une ligne indentée (espace/tab) non vide.
    Leur texte (déjà *stripé*) est joint au texte de l'élément avec un espace
    afin que ``_inline`` puisse convertir des balises **gras** s'étendant sur
    plusieurs lignes.

    Renvoie ``(texte_complet, indice_de_la_ligne_suivante)``.
    """
    text = first_text
    i += 1
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if not s:
            break
        if raw[0] in ' \t':
            text += " " + s
            i += 1
        else:
            break
    return text, i


def _parse_table(lines: list, i: int):
    """Si lines[i:...] forme une table markdown, renvoie (html, j) sinon (None, i)."""
    if "|" not in lines[i]:
        return None, i
    if i + 1 >= len(lines):
        return None, i
    sep = lines[i + 1].strip()
    # Ligne de séparation : --- / :--- / :---: etc., colonnes séparées par |.
    if not re.match(r"^[|\s:\-]+$", sep) or "-" not in sep:
        return None, i

    header = _split_row(lines[i])
    rows = []
    j = i + 2
    while j < len(lines) and "|" in lines[j]:
        rows.append(_split_row(lines[j]))
        j += 1

    html_rows = ["<table>", "<tr>"]
    for cell in header:
        html_rows.append(f"<th>{_inline(cell)}</th>")
    html_rows.append("</tr>")
    for row in rows:
        html_rows.append("<tr>")
        for cell in row:
            html_rows.append(f"<td>{_inline(cell)}</td>")
        html_rows.append("</tr>")
    html_rows.append("</table>")
    return "\n".join(html_rows), j


def md_to_html(md_text: str) -> str:
    """Convertit un document Markdown complet en fragment HTML de corps."""
    lines = md_text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        tbl, next_i = _parse_table(lines, i)
        if tbl is not None:
            out.append(tbl)
            i = next_i
            continue

        if not stripped:
            out.append("")
            i += 1
            continue

        # Titres
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2).strip())}</h{level}>")
            i += 1
            continue

        # Bloc de code fencé
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1  # saute la ligne de clôture
            out.append(f"<pre><code>{_esc(chr(10).join(block))}</code></pre>")
            continue

        # Liste à puces
        m = re.match(r"^([-*+])\s+(.*)$", stripped)
        if m:
            text, i = _join_continued_item(lines, i, m.group(2))
            out.append(f"<ul><li>{_inline(text)}</li></ul>")
            continue

        # Liste numérotée
        m = re.match(r"^(\d+)[.)]\s+(.*)$", stripped)
        if m:
            text, i = _join_continued_item(lines, i, m.group(2))
            out.append(f"<ol><li>{_inline(text)}</li></ol>")
            continue

        # Citation
        if stripped.startswith(">"):
            out.append(f"<blockquote>{_inline(stripped.lstrip('> '))}</blockquote>")
            i += 1
            continue

        # Règle horizontale
        if stripped in ("---", "***", "___"):
            out.append("<hr>")
            i += 1
            continue

        # Paragraphe
        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    return "\n".join(out)


def build_document(md_text: str, title: str, css_path: str = None) -> str:
    """Construit la page HTML complète (en-tête, CSS optionnel, corps)."""
    css = ""
    if css_path and os.path.isfile(css_path):
        with open(css_path, "r", encoding="utf-8") as fh:
            css = fh.read()
    style = f"<style>\n{css}\n</style>" if css.strip() else ""
    body = md_to_html(md_text)
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
{style}
</head>
<body class="print">
<div class="doc">
<h1>{_esc(title)}</h1>
{body}
<footer>Généré par CodeScan — manuel imprimable.</footer>
</div>
</body>
</html>"""


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(
        description="Markdown -> HTML imprimable (stdlib).")
    ap.add_argument("input", metavar="FICHIER.md")
    ap.add_argument("output", metavar="FICHIER.html")
    ap.add_argument("--css", default=None, help="Feuille CSS a embarquer.")
    ap.add_argument("--title", default="Manuel CodeScan",
                    help="Titre de la page.")
    args = ap.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        md = fh.read()
    page = build_document(md, args.title, args.css)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"[make_to_html] {args.output} écrit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
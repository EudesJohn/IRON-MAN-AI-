"""Tests des utilitaires de génération des manuels (HTML autonome + PDF).

L'essentiel est vérifiable sans navigateur : la conversion markdown ->
HTML autonome (make_to_html). Le rendu PDF headless n'est testé que si un
navigateur Chromium-compatible est détecté (sinon skip).
"""

import importlib.util
import os
import sys
import tempfile
import unittest

DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(DOCS_DIR, fname))
    mod = importlib.util.module_from_spec(spec)
    # make_pdf importe make_to_html : docs/ doit être dans sys.path.
    if DOCS_DIR not in sys.path:
        sys.path.insert(0, DOCS_DIR)
    try:
        spec.loader.exec_module(mod)
    finally:
        if DOCS_DIR in sys.path:
            sys.path.remove(DOCS_DIR)
    return mod


make_to_html = _load("make_to_html", "make_to_html.py")
make_pdf = _load("make_pdf", "make_pdf.py")

SAMPLE_MD = """# Titre principal

## Sous-titre

Paragraphe avec du **gras** et du `code`.

Mixte valeureux : 1 < 2 et a & b.

- puce un
- puce deux

1. premier
2. second

> Une citation.

```
python
x = 1
```

| Outil | Binaire |
|-------|---------|
| nmap  | nmap    |
"""


class TestMarkdownToHtml(unittest.TestCase):
    def test_basic_structure(self):
        page = make_to_html.build_document(SAMPLE_MD, "Exemple")
        self.assertIn("<!DOCTYPE html>", page)
        self.assertIn("<h1>Exemple</h1>", page)
        self.assertIn("</html>", page)
        # Plus aucun bloc fenced brut ne subsiste.
        self.assertNotIn("```", page)

    def test_expected_elements(self):
        body = make_to_html.md_to_html(SAMPLE_MD)
        self.assertIn("<h2>Sous-titre</h2>", body)
        self.assertIn("<strong>gras</strong>", body)
        self.assertIn("<code>code</code>", body)
        self.assertIn("<ul><li>puce un</li></ul>", body)
        self.assertIn("<ol><li>premier</li></ol>", body)
        self.assertIn("<blockquote>Une citation.</blockquote>", body)
        self.assertIn("<pre><code>", body)
        self.assertIn("<table>", body)

    def test_escaping(self):
        body = make_to_html.md_to_html("<script>alert(1)</script>")
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)


MANUALS = [
    "MANUEL_KALI.md",
    "MANUEL_WINDOWS.md",
    "MANUEL_WIFI.md",
    "MANUEL_ANDROID.md",
    "MANUEL_DEVICE.md",
    "MANUEL_CONTROLE.md",
    os.path.join("..", "MANUEL.md"),  # manuel principal (racine du projet)
]


class TestManualsConvert(unittest.TestCase):
    def test_each_manual_produces_self_contained_html(self):
        for rel in MANUALS:
            fname = os.path.basename(rel)
            path = os.path.join(DOCS_DIR, rel)
            self.assertTrue(os.path.isfile(path), f"manuel absent : {rel}")
            with open(path, encoding="utf-8") as fh:
                md = fh.read()
            self.assertTrue(md.strip(), f"manuel vide : {rel}")
            page = make_to_html.build_document(md, fname,
                                               os.path.join(DOCS_DIR, "manuel.css"))
            self.assertIn("<!DOCTYPE html>", page)
            self.assertIn("<div class=\"doc\">", page)
            self.assertIn("</html>", page)
            self.assertNotIn("```", page, rel)
            self.assertNotIn("**", page, rel)

    def test_css_embedded(self):
        path = os.path.join(DOCS_DIR, "MANUEL_KALI.md")
        with open(path, encoding="utf-8") as fh:
            md = fh.read()
        page = make_to_html.build_document(md, "x",
                                           os.path.join(DOCS_DIR, "manuel.css"))
        self.assertIn("@media print", page)
        self.assertIn("@page", page)

    def test_combined_manual_assembles_all_sections(self):
        """Le PDF unique (make_pdf_all) assemble tous les manuels."""
        make_pdf_all = _load("make_pdf_all", "make_pdf_all.py")
        html = make_pdf_all.build_combined_html(
            os.path.join(DOCS_DIR, "manuel.css"))
        self.assertIn("Manuel complet", html)
        self.assertIn("<div class=\"section\">", html)
        # chaque manuel du projet doit être présent dans la page unique
        for title, rel in make_pdf_all.MANUALS:
            path = os.path.join(make_pdf_all.PROJECT_ROOT, rel)
            with open(path, encoding="utf-8") as fh:
                md = fh.read()
            h1 = make_pdf_all._first_h1(md)
            self.assertTrue(h1, f"pas de H1 dans {rel}")
            self.assertIn(h1, html, f"section manquante : {rel}")

    def test_combined_manual_bundles_kali_windows(self):
        """Les bundles Kali/Windows excluent le guide de l'autre plateforme."""
        make_pdf_all = _load("make_pdf_all", "make_pdf_all.py")
        self.assertEqual(
            {rel for _, rel in make_pdf_all.BUNDLES["kali"][0]},
            {rel for _, rel in make_pdf_all.MANUALS}
            - {"docs/MANUEL_WINDOWS.md"})
        self.assertEqual(
            {rel for _, rel in make_pdf_all.BUNDLES["windows"][0]},
            {rel for _, rel in make_pdf_all.MANUALS}
            - {"docs/MANUEL_KALI.md"})
        html = make_pdf_all.build_combined_html(
            os.path.join(DOCS_DIR, "manuel.css"),
            manuals=make_pdf_all.BUNDLES["kali"][0])
        self.assertIn("Manuel complet (Kali)", html)
        # le H1 du manuel exclu ne doit pas apparaître comme section
        md_win = open(os.path.join(DOCS_DIR, "MANUEL_WINDOWS.md"),
                      encoding="utf-8").read()
        h1_win = make_pdf_all._first_h1(md_win)
        self.assertNotIn(h1_win, html)


@unittest.skipUnless(make_pdf.find_browser(), "aucun navigateur Chromium disponible")
class TestPdfGeneration(unittest.TestCase):
    def test_pdf_produced_from_manual(self):
        md_path = os.path.join(DOCS_DIR, "MANUEL_KALI.md")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "manuel.pdf")
            rc = make_pdf.make_pdf(md_path, out, css=os.path.join(DOCS_DIR,
                                                                  "manuel.css"))
            self.assertEqual(rc, 0, "le PDF doit être généré avec le navigateur")
            self.assertTrue(out.endswith(".pdf"))
            with open(out, "rb") as fh:
                head = fh.read(5)
            self.assertEqual(head, b"%PDF-")


if __name__ == "__main__":
    unittest.main()
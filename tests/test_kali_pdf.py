"""Tests du générateur PDF stdlib (kali.pdf) — audit complet IRON MAN AI.

On vérifie la structure PDF (en-tête, xref, startxref), la compression
FlateDecode (chacun des flux se décompresse et contient le texte attendu),
l'échappement des parenthèses et la conversion WinAnsi des accents.
"""

import os
import re
import tempfile
import unittest
import zlib

from scanner.models import Finding
from kali.pdf import build_pdf_bytes, write_web_pdf

_TARGET = "http://example.com/"
_META = {"tool": "IRON MAN AI", "version": "1.4.0",
         "timestamp": "2026-08-08T10:00:00"}
_BY_TOOL = {
    "sqlmap": {"ok": True, "status": "ok", "duration_sec": 12.5, "count": 1},
    "nmap": {"ok": True, "status": "ok", "duration_sec": 3.0, "count": 1},
}
_PREFLIGHT = {"sqlmap": {"present": True, "bin": "sqlmap"},
              "nmap": {"present": False, "bin": "nmap"}}


def _findings():
    return [
        Finding(
            file=_TARGET, line=0, rule_id="web-sqlmap-injectable",
            category="security_misc", severity="critical",
            title="Injection SQL détectée (paramètre id)",
            description="Le paramètre id est concaténé dans une requête.",
            recommendation="Utiliser des requêtes préparées.",
            snippet="SELECT * FROM produits WHERE id = '1' OR '1'='1'",
            language="html", source="sqlmap"),
        Finding(file=_TARGET, line=0, rule_id="web-nmap-open-port",
                category="security_misc", severity="medium",
                title="Port 8080 ouvert", description="Service inconnu.",
                recommendation="Filtrer le port.",
                snippet="8080/tcp open", language="html", source="nmap"),
    ]


def _streams(data: bytes) -> list:
    """"Renvoie les flux FlateDecode décompressés (contenu texte décompressé)."""
    raw = re.findall(rb"stream\n(.*?)\nendstream", data, re.DOTALL)
    return [zlib.decompress(s) for s in raw]


class TestPdfStructure(unittest.TestCase):
    def test_header_and_eof(self):
        data = build_pdf_bytes(_findings(), _BY_TOOL, _TARGET, _META,
                               _PREFLIGHT, score={"score": 45, "grade": "D"})
        self.assertTrue(data.startswith(b"%PDF-1.4"), data[:20])
        self.assertIn(b"%%EOF", data)
        self.assertIn(b"startxref", data)

    def test_xref_integrity(self):
        data = build_pdf_bytes(_findings(), _BY_TOOL, _TARGET, _META, _PREFLIGHT)
        obj_ids = [int(m) for m in re.findall(rb"(\d+) 0 obj", data)]
        self.assertGreater(len(obj_ids), 3)
        # Le trailer /Size = nombre d'objets + 1 (l'entrée libre tête de xref).
        size = int(re.search(rb"/Size (\d+)", data).group(1))
        self.assertEqual(size, len(obj_ids) + 1)
        # Chaque offset du xref pointe bien sur "N 0 obj".
        xref_offsets = [int(m.group(1)) for m in re.finditer(rb"(?m)^(\d{10}) 00000 n ",
                                                             data)]
        self.assertEqual(len(xref_offsets), len(obj_ids))
        for i, off in enumerate(xref_offsets):
            expect = data.find(f"{i + 1} 0 obj".encode())
            self.assertEqual(off, expect, f"offset objet {i + 1} erroné")

    def test_pages_present(self):
        data = build_pdf_bytes(_findings(), _BY_TOOL, _TARGET, _META, _PREFLIGHT)
        self.assertGreaterEqual(data.count(b"/Type /Page"), 1)


class TestPdfContent(unittest.TestCase):
    def test_content_mentions_expected_text(self):
        data = build_pdf_bytes(_findings(), _BY_TOOL, _TARGET, _META, _PREFLIGHT,
                               score={"score": 45, "grade": "D"})
        streams = b"".join(_streams(data))  # concatène pour grep simple
        for needle in (b"IRON MAN AI", b"http://example.com/",
                       b"web-sqlmap-injectable", b"[CRITICAL]", b"[MEDIUM]",
                       b"Score", "préparées".encode("latin-1")):
            self.assertIn(needle, streams, needle.decode("latin-1"))

    def test_escaped_parentheses_do_not_break(self):
        fs = [Finding(file=_TARGET, line=0, rule_id="web-x",
                      severity="low", title="Titre (avec) des parenthèses)",
                      source="nmap")]
        data = build_pdf_bytes(fs, _BY_TOOL, _TARGET, _META, _PREFLIGHT)
        self.assertTrue(data.endswith(b"%%EOF\n"))
        body = b"".join(_streams(data))
        self.assertIn("parenthèses".encode("latin-1"), body)

    def test_winansi_accents_preserved(self):
        fs = [Finding(file=_TARGET, line=0, rule_id="web-x",
                       severity="high", title="Préparation",
                       description="Résumé d'évaluation",
                       source="nmap")]
        data = build_pdf_bytes(fs, _BY_TOOL, _TARGET, _META, _PREFLIGHT)
        body = b"".join(_streams(data))
        self.assertIn("Préparation".encode("latin-1"), body)
        self.assertIn("évaluation".encode("latin-1"), body)
        # Aucun caractère hors latin-1 ne doit fausser la structure.
        self.assertNotIn(b"\xff", body)

    def test_empty_findings_still_pdf(self):
        data = build_pdf_bytes([], _BY_TOOL, _TARGET, _META, _PREFLIGHT)
        self.assertTrue(data.startswith(b"%PDF-1.4"))


class TestWriteWebPdf(unittest.TestCase):
    def test_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.pdf")
            write_web_pdf(_findings(), _BY_TOOL, _TARGET, _META, _PREFLIGHT,
                          path)
            with open(path, "rb") as fh:
                data = fh.read()
        self.assertGreater(len(data), 100)
        self.assertTrue(data.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
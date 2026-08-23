"""Tests du rapport WebScan Kali (JSON + HTML, mêmes conventions que le
rapport statique : meta, summary, score, findings)."""

import json
import os
import tempfile
import unittest

from scanner.models import Finding
from kali.report import web_stats, build_meta, write_web_report
from kali.parsers import parse_output, PARSERS

TARGET = {"url": "http://example.com/", "host": "example.com",
          "scheme": "http", "port": 80, "path": "/", "domain": "example.com"}

NMAP_OUT = ("80/tcp   open  http   Apache httpd 2.4.41\n"
            "443/tcp  open  ssl    nginx 1.18.0\n")


def _findings():
    return parse_output("nmap", NMAP_OUT, TARGET)


_BY_TOOL = {"nmap": {"status": "ok", "ok": True, "duration_sec": 3.2,
                     "count": 2}}
_PREFLIGHT = {"nmap": {"present": True, "bin": "nmap"}}


class TestWebStats(unittest.TestCase):
    def test_counts(self):
        fs = _findings()
        stats = web_stats(fs, _BY_TOOL)
        self.assertEqual(stats["total_findings"], len(fs))
        self.assertEqual(stats["files_scanned"], 1)  # nb d'outils, min 1
        self.assertEqual(stats["by_severity"]["low"], len(fs))

    def test_empty_findings(self):
        stats = web_stats([], {})
        self.assertEqual(stats["total_findings"], 0)
        self.assertEqual(stats["files_scanned"], 1)  # ne divise jamais par 0


class TestBuildMeta(unittest.TestCase):
    def test_meta_fields(self):
        meta = build_meta("http://example.com/", attack=False, version="1.2.0")
        self.assertEqual(meta["mode"], "web")
        self.assertEqual(meta["target"], "http://example.com/")
        self.assertFalse(meta["attack"])
        self.assertEqual(meta["tool"], "IRON MAN AI")
        self.assertIn("timestamp", meta)

    def test_meta_attack_flag(self):
        self.assertTrue(build_meta("http://x", attack=True, version="1.2.0")["attack"])


class TestWriteWebReport(unittest.TestCase):
    def test_json_report_keys(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rapport.json")
            write_web_report(_findings(), _BY_TOOL, "http://example.com/", False,
                             _PREFLIGHT, path, "1.2.0")
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        self.assertIn("score", data)
        self.assertIn("meta", data)
        self.assertEqual(data["meta"]["mode"], "web")
        self.assertTrue(data["findings"])
        self.assertEqual(data["findings"][0]["rule_id"], "web-nmap-open-port")

    def test_html_report_markers(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rapport.html")
            write_web_report(_findings(), _BY_TOOL, "http://example.com/", False,
                             _PREFLIGHT, path, "1.2.0")
            with open(path, encoding="utf-8") as fh:
                html = fh.read()
        for marker in (
            "<!DOCTYPE html>",
            "IRON MAN AI",
            "Préflight",
            "Résultats par outil",
            "web-nmap-open-port",
            "</html>",
        ):
            self.assertIn(marker, html, marker)

    def test_unsupported_extension_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rapport.txt")
            with self.assertRaises(ValueError):
                write_web_report([], _BY_TOOL, "http://example.com/", False,
                                 {}, path, "1.2.0")


if __name__ == "__main__":
    unittest.main()
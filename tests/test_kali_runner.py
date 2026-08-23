"""Tests de l'exécution sûre des outils (runner) et du dry-run.

Aucun outil Kali réel n'est exécuté : seulement des commandes Python
(binaires `sys.executable`) pour tester timeout et capture, et le mode
`--dry-run` qui ne doit jamais appeler `subprocess`.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

from kali.runner import (
    ToolResult, make_tmp_dir, run_one, dry_run_commands,
)
from kali.wordlist import wordlist_path, EMBEDDED

TARGET = {"url": "http://example.com/", "host": "example.com",
          "scheme": "http", "port": 80, "path": "/", "domain": "example.com"}


class TestToolResult(unittest.TestCase):
    def test_ok_only_rc_zero(self):
        self.assertTrue(ToolResult("x", ["cmd"], rc=0).ok)
        self.assertFalse(ToolResult("x", ["cmd"], rc=1).ok)
        self.assertFalse(ToolResult("x", ["cmd"], rc=0, timed_out=True).ok)

    def test_status_strings(self):
        self.assertEqual(ToolResult("x", "c", rc=0).status, "ok")
        self.assertEqual(ToolResult("x", "c", rc=2).status, "erreur (rc=2)")
        self.assertEqual(ToolResult("x", "c", timed_out=True).status, "timeout")
        self.assertEqual(ToolResult("x", "c", missing=True).status, "introuvable")

    def test_to_dict_shape(self):
        d = ToolResult("nmap", ["nmap", "x"], rc=0, duration=2.3).to_dict()
        self.assertEqual(d["name"], "nmap")
        self.assertEqual(d["cmd"], "nmap x")
        self.assertEqual(d["status"], "ok")


class TestRunOne(unittest.TestCase):
    def test_success_captures_stdout(self):
        r = run_one("demo", [sys.executable, "-c", "print('bonjour')"], timeout=10)
        self.assertEqual(r.rc, 0)
        self.assertIn("bonjour", r.stdout)
        self.assertTrue(r.ok)

    def test_missing_binary_reported_and_skipped(self):
        r = run_one("inexistant_xyz", ["commande_qui_n_existe_pas_xyz"], timeout=10)
        self.assertTrue(r.missing)
        self.assertEqual(r.status, "introuvable")

    def test_empty_command_means_missing(self):
        r = run_one("vide", [], timeout=10)
        self.assertTrue(r.missing)

    def test_timeout_is_captured(self):
        code = "import time; time.sleep(5)"
        r = run_one("lent", [sys.executable, "-c", code], timeout=1)
        self.assertTrue(r.timed_out, "le timeout doit être détecté")
        self.assertEqual(r.status, "timeout")
        self.assertFalse(r.ok)

    def test_writes_raw_log_when_tmp_given(self):
        with tempfile.TemporaryDirectory() as d:
            r = run_one("demo", [sys.executable, "-c", "print('log')"], timeout=10,
                        tmp_dir=d)
            diff = os.path.join(d, "demo.txt")
            self.assertEqual(r.stdout.strip(), "log")
            self.assertTrue(os.path.isfile(diff))


class TestTmpDir(unittest.TestCase):
    def test_make_tmp_dir_creates(self):
        with tempfile.TemporaryDirectory() as d:
            path = make_tmp_dir(base=d)
            self.assertTrue(os.path.isdir(path))
            # daté horodatage : répertoire enfant sous la base.
            self.assertEqual(os.path.dirname(path), d)


class TestWordlistPath(unittest.TestCase):
    def test_prefers_kali_wordlist_when_it_exists(self):
        with mock.patch("kali.wordlist.os.path.isfile", return_value=True):
            self.assertEqual(
                wordlist_path("/usr/share/wordlists/dirb/common.txt"),
                "/usr/share/wordlists/dirb/common.txt")

    def test_writes_embedded_list_when_kali_missing(self):
        # Hermétique : on simule l'absence de la wordlist Kali à la fois
        # pour isfile ET pour la lecture (sinon, sur une machine où
        # /usr/share/wordlists/dirb/common.txt existe, le vrai fichier
        # serait lu et le test échouerait).
        d = None
        with mock.patch("kali.wordlist.os.path.isfile", return_value=False), \
             mock.patch("kali.wordlist.resolve_wordlist",
                        return_value=list(EMBEDDED)):
            with tempfile.TemporaryDirectory() as dtmp:
                d = dtmp
                path = wordlist_path(tmp_dir=dtmp)
                with open(path, encoding="utf-8") as fh:
                    content = fh.read()
        self.assertTrue(path.startswith(os.path.abspath(d)))
        self.assertIn("/admin", content)
        # Tous les mots embarqués sont écrits (fichier utilisable par les outils).
        for word in EMBEDDED:
            self.assertIn(word, content)

    def test_no_tmp_dir_returns_preferred(self):
        with mock.patch("kali.wordlist.os.path.isfile", return_value=False):
            self.assertEqual(wordlist_path("/nope/common.txt", tmp_dir=None),
                             "/nope/common.txt")


class TestToolTimeoutOption(unittest.TestCase):
    """Option --tool-timeout : borne raisonnable en mode maximal."""

    def test_parser_accepts_tool_timeout(self):
        from kali_scan import build_parser
        args = build_parser().parse_args(
            ["--url", "http://example.com", "--tool-timeout", "600"])
        self.assertEqual(args.tool_timeout, 600)

    def test_tool_timeout_default_none(self):
        from kali_scan import build_parser
        args = build_parser().parse_args(["--url", "http://example.com"])
        self.assertIsNone(args.tool_timeout)


class TestDryRun(unittest.TestCase):
    def test_dry_run_never_executes(self):
        from kali.tools import all_tools
        tools = list(all_tools(attack=False))
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("kali.runner.subprocess.run") as sub:
                lines = dry_run_commands(tools, TARGET, d, wordlist=None)
        sub.assert_not_called()
        self.assertEqual(len(lines), len(tools))
        for line in lines:
            name = line.split()[0]
            self.assertIn(name, {n for n, _ in tools})

    def test_hydra_disabled_without_wordlists(self):
        from kali.tools import TOOLS
        with tempfile.TemporaryDirectory() as d:
            lines = dry_run_commands([("hydra", TOOLS["hydra"])], TARGET, d,
                                     wordlist=None)
        self.assertIn("desactive (wordlists requises)", lines[0])

    def test_commands_contain_target(self):
        from kali.tools import TOOLS
        with tempfile.TemporaryDirectory() as d:
            lines = dry_run_commands([("nmap", TOOLS["nmap"])], TARGET, d)
        self.assertIn("example.com", lines[0])
        self.assertIn("->", lines[0])
        self.assertTrue(lines[0].startswith("nmap"))


if __name__ == "__main__":
    unittest.main()
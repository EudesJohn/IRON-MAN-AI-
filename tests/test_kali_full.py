"""Tests du mode maximal d'IRON MAN AI et de la commande unique.

Couvre : commandes maximales (nmap -p- -sC, sqlmap --level 3 --risk 3,
threads élevés), wordlist complète (max_words=None), chemins des rapports
(JSON/HTML/PDF), défauts de la CLI (ironman.py = tout à fond) et runner
avec timeout=None (aucune limite de temps).
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

from kali.tools import TOOLS, all_tools
from kali.wordlist import resolve_wordlist, EMBEDDED
from kali.urls import split_target
from kali.runner import run_one

TARGET = split_target("http://example.com/")


def _ctx(maximal=True, wordlist="/w.txt"):
    return {"tmp": "/tmp", "wordlist": wordlist, "maximal": maximal,
            "hydra_users": None, "hydra_passwords": None}


class TestMaximalCommands(unittest.TestCase):
    def test_nmap_maximal_full_ports(self):
        cmd = TOOLS["nmap"]["cmd"](TARGET, _ctx(maximal=True))
        self.assertIn("-p-", cmd)
        self.assertIn("-sC", cmd)
        self.assertNotIn("--top-ports", cmd)

    def test_nmap_normal_limited_ports(self):
        cmd = TOOLS["nmap"]["cmd"](TARGET, _ctx(maximal=False))
        self.assertIn("--top-ports", cmd)
        self.assertNotIn("-p-", cmd)

    def test_gobuster_threads(self):
        cmd = TOOLS["gobuster"]["cmd"](TARGET, _ctx(True))
        self.assertEqual(cmd[cmd.index("-t") + 1], "64")
        cmd = TOOLS["gobuster"]["cmd"](TARGET, _ctx(False))
        self.assertEqual(cmd[cmd.index("-t") + 1], "16")

    def test_dirsearch_threads_only_maximal(self):
        self.assertIn("--threads",
                      TOOLS["dirsearch"]["cmd"](TARGET, _ctx(True)))
        self.assertNotIn("--threads",
                         TOOLS["dirsearch"]["cmd"](TARGET, _ctx(False)))

    def test_sqlmap_maximal_level_risk(self):
        cmd = TOOLS["sqlmap"]["cmd"](TARGET, _ctx(True))
        self.assertIn("--level", cmd)
        self.assertEqual(cmd[cmd.index("--level") + 1], "3")
        self.assertEqual(cmd[cmd.index("--risk") + 1], "3")

    def test_sqlmap_normal_level_risk(self):
        cmd = TOOLS["sqlmap"]["cmd"](TARGET, _ctx(False))
        self.assertEqual(cmd[cmd.index("--level") + 1], "1")
        self.assertEqual(cmd[cmd.index("--risk") + 1], "1")

    def test_commix_maximal_level(self):
        cmd = TOOLS["commix"]["cmd"](TARGET, _ctx(True))
        self.assertEqual(cmd[cmd.index("--level") + 1], "3")
        cmd = TOOLS["commix"]["cmd"](TARGET, _ctx(False))
        self.assertEqual(cmd[cmd.index("--level") + 1], "1")

    def test_hydra_needs_wordlists(self):
        ctx = dict(_ctx(True))
        self.assertIsNone(TOOLS["hydra"]["cmd"](TARGET, ctx))
        ctx["hydra_users"] = "/u.txt"
        ctx["hydra_passwords"] = "/p.txt"
        self.assertIsNotNone(TOOLS["hydra"]["cmd"](TARGET, ctx))


class TestMaximalWordlist(unittest.TestCase):
    def test_max_words_none_returns_full_list(self):
        words = resolve_wordlist("/fichier/inexistant.txt", max_words=None)
        self.assertEqual(words, EMBEDDED)  # a back-up : liste complète embarquée
        self.assertGreaterEqual(len(words), 10)

    def test_max_words_2_caps_list(self):
        words = resolve_wordlist("/fichier/inexistant.txt", max_words=2)
        self.assertEqual(words, list(EMBEDDED[:2]))

    def test_kali_wordlist_full_not_capped(self):
        # Un fichier Kali factice doit être lu *en entier* avec max_words=None.
        with tempfile.TemporaryDirectory() as d:
            wl = os.path.join(d, "common.txt")
            with open(wl, "w", encoding="utf-8") as fh:
                fh.write("word1\n# comment\nword2\nword3\n")
            full = resolve_wordlist(wl, max_words=None)
            self.assertEqual(full, ["word1", "word2", "word3"])
            capped = resolve_wordlist(wl, max_words=2)
            self.assertEqual(capped, ["word1", "word2"])


class TestRunnerNoTimeout(unittest.TestCase):
    def test_timeout_none_runs_to_completion(self):
        r = run_one("demo", [sys.executable, "-c", "print('fini')"],
                    timeout=None)
        self.assertTrue(r.ok)
        self.assertIn("fini", r.stdout)

    def test_timeout_none_long_running_not_killed(self):
        r = run_one("lent", [sys.executable, "-c",
                             "import time; time.sleep(1); print('ok')"],
                    timeout=None)
        self.assertTrue(r.ok)
        self.assertEqual(r.status, "ok")


class TestOutputPaths(unittest.TestCase):
    def test_output_only(self):
        from kali_scan import _output_paths
        self.assertEqual(_output_paths("r.json", False), [("r.json", ".json")])
        self.assertEqual(_output_paths("r.html", False), [("r.html", ".html")])

    def test_output_plus_pdf(self):
        from kali_scan import _output_paths
        self.assertEqual(_output_paths("r.json", True),
                         [("r.json", ".json"), ("r.pdf", ".pdf")])

    def test_pdf_alone_produces_complete(self):
        from kali_scan import _output_paths
        # Sans --output : rapports dans le dossier central rapports/
        # (horodatés) — base commune, extensions .json/.html/.pdf.
        outs = _output_paths(None, True)
        self.assertEqual([ext for _, ext in outs],
                         [".json", ".html", ".pdf"])
        bases = {os.path.splitext(p)[0] for p, _ in outs}
        self.assertEqual(len(bases), 1)
        base = bases.pop()
        self.assertIn(os.sep + "rapports" + os.sep, base)
        self.assertIn("audit_web_", base)

    def test_nothing(self):
        from kali_scan import _output_paths
        self.assertEqual(_output_paths(None, False), [])


class TestIronmanDefaults(unittest.TestCase):
    def test_command_unique_active_max(self):
        from kali_scan import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        self.assertTrue(args.full)
        self.assertTrue(args.attack)
        self.assertTrue(args.pdf)

    def test_kali_scan_switches_back_to_normal(self):
        from kali_scan import build_parser
        parser = build_parser()
        parser.set_defaults(full=False, pdf=False, attack=False)
        args = parser.parse_args([])
        self.assertFalse(args.full)
        self.assertFalse(args.attack)

    def test_ironman_dry_run_no_network(self):
        with mock.patch("kali.preflight.shutil.which", return_value=None):
            from ironman import main
            rc = main(["--url", "http://example.com/", "--authorized",
                       "--dry-run"])
        self.assertEqual(rc, 0)

    def test_kaliscan_dry_run_no_network(self):
        with mock.patch("kali.preflight.shutil.which", return_value=None):
            from kali_scan import main
            rc = main(["--url", "http://example.com/", "--authorized",
                       "--dry-run"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
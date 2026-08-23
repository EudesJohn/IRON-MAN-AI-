"""Tests du préflight WebScan Kali (présence des outils, commandes apt)."""

import unittest
from unittest import mock

from kali.preflight import (
    check_tools, install_commands, missing_tools, install_text,
)
from kali.tools import all_tools, applies, TOOLS
from kali.urls import split_target, netloc


class TestPreflight(unittest.TestCase):
    def test_check_tools_with_all_present(self):
        with mock.patch("kali.preflight.shutil.which", return_value="/usr/bin/nmap"):
            status = check_tools(attack=False)
        self.assertTrue(len(status) > 0)
        for info in status.values():
            self.assertTrue(info["present"], info["bin"])
            self.assertNotIn("MANQUANT", install_text(status))

    def test_check_tools_with_all_missing(self):
        with mock.patch("kali.preflight.shutil.which", return_value=None):
            status = check_tools(attack=False)
        missing = missing_tools(status)
        self.assertEqual(len(missing), len(status))
        cmds = install_commands(missing)
        self.assertEqual(cmds[0], "sudo apt-get update")
        self.assertTrue(cmds[1].startswith("sudo apt-get install -y "))
        for _, info in missing:
            self.assertIn(info["apt"], cmds[1])

    def test_check_tools_attack_gates_output(self):
        # Sans --attack, aucun outil invasif (sqlmap, xsstrike, commix, hydra).
        names_web = {name for name, _ in all_tools(attack=False)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertNotIn(invasive, names_web)
        names_attack = {name for name, _ in all_tools(attack=True)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertIn(invasive, names_attack)

    def test_install_text_mentions_apt_package(self):
        with mock.patch("kali.preflight.shutil.which", side_effect=lambda b: None):
            status = check_tools(attack=False)
        text = install_text(status)
        self.assertIn("sudo apt-get install -y", text)
        # Chaque outil manquant a sa ligne  ->  sudo apt-get install -y <apt>
        for name, _ in missing_tools(status):
            self.assertIn(f"sudo apt-get install -y {TOOLS[name]['apt']}", text)


class TestUrls(unittest.TestCase):
    def test_split_target_normalizes(self):
        t = split_target("https://www.example.com:8443/path?x=1")
        self.assertEqual(t["host"], "www.example.com")
        self.assertEqual(t["scheme"], "https")
        self.assertEqual(t["port"], 8443)
        self.assertEqual(t["domain"], "example.com")  # www. retiré
        self.assertIn("8443", t["url"])
        self.assertTrue(t["url"].startswith("https://"))

    def test_split_target_adds_scheme_and_defaults(self):
        t = split_target("example.com")
        self.assertEqual(t["scheme"], "http")
        self.assertEqual(t["port"], 80)
        self.assertEqual(t["host"], "example.com")

    def test_netloc_omits_standard_port(self):
        self.assertEqual(netloc({"scheme": "http", "host": "a.com", "port": 80}),
                         "a.com")
        self.assertEqual(netloc({"scheme": "https", "host": "a.com", "port": 443}),
                         "a.com")
        self.assertEqual(netloc({"scheme": "https", "host": "a.com", "port": 8443}),
                         "a.com:8443")


class TestTools(unittest.TestCase):
    def test_applies_sslscan_only_https(self):
        self.assertTrue(applies(TOOLS["sslscan"], {"scheme": "https"}))
        self.assertFalse(applies(TOOLS["sslscan"], {"scheme": "http"}))

    def test_all_tools_order_is_defined(self):
        names = [n for n, _ in all_tools(attack=True)]
        self.assertEqual(names[0], "nmap")
        self.assertIn("nuclei", names)

    def test_binary_field_exists(self):
        for name, _ in all_tools(attack=True):
            self.assertEqual(TOOLS[name]["bin"], name)


if __name__ == "__main__":
    unittest.main()
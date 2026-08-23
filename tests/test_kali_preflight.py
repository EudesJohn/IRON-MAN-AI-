"""Tests du préflight WebScan Kali (présence des outils, commandes d'installation multi-OS)."""

import unittest
from unittest import mock

from kali.preflight import (
    check_tools, install_commands, missing_tools, install_text, _detect_os,
    _WINDOWS_ALTERNATIVES,
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

    def test_check_tools_with_all_missing_linux(self):
        """Sur Linux, tous les outils manquants sont vraiment manquants (pas d'alternative)."""
        with mock.patch("kali.preflight.which", return_value=None), \
             mock.patch("kali.preflight._detect_os", return_value=("linux", "Linux")):
            status = check_tools(attack=False)
            # Sur Linux, il n'y a pas d'alternative Windows
            really_missing = [(n, i) for n, i in status.items()
                              if not i["present"] and not i.get("alt_present")]
            # Tous devraient etre vraiment manquants
            self.assertEqual(len(really_missing), len(status))
            cmds = install_commands(really_missing)
            self.assertEqual(cmds[0], "sudo apt-get update")
            self.assertTrue(cmds[1].startswith("sudo apt-get install -y "))
            for _, info in really_missing:
                self.assertIn(info["apt"], cmds[1])

    def test_check_tools_with_all_missing_windows(self):
        """Sur Windows, certains outils ont des alternatives Python."""
        # Simule un systeme ou les outils Linux n'existent pas,
        # mais les alternatives Python (whatweb, dirsearch) sont installees.
        def mock_which(name):
            if name in ("whatweb", "dirsearch", "dirsearch.exe"):
                return f"/fake/{name}"
            return None

        with mock.patch("kali.preflight.which", side_effect=mock_which), \
             mock.patch("kali.preflight._detect_os", return_value=("windows", "Windows")):
            status = check_tools(attack=False)
            # Sur Windows, certains outils ont des alternatives
            really_missing = [(n, i) for n, i in status.items()
                              if not i["present"] and not i.get("alt_present")]
            # Les outils avec alternatives ne sont pas "manquants"
            self.assertLess(len(really_missing), len(status))
            # Les outils avec alternatives sont identifies
            for name, info in status.items():
                if name in _WINDOWS_ALTERNATIVES and _WINDOWS_ALTERNATIVES[name]:
                    # Ce outil a une alternative, il ne devrait pas etre dans really_missing
                    self.assertFalse(any(n == name for n, _ in really_missing),
                                     f"{name} ne devrait pas etre manquant (a une alternative)")

    def test_check_tools_attack_gates_output(self):
        # Sans --attack, aucun outil invasif (sqlmap, xsstrike, commix, hydra).
        names_web = {name for name, _ in all_tools(attack=False)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertNotIn(invasive, names_web)
        names_attack = {name for name, _ in all_tools(attack=True)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertIn(invasive, names_attack)

    def test_install_text_mentions_apt_package_linux(self):
        with mock.patch("kali.preflight.which", return_value=None), \
             mock.patch("kali.preflight._detect_os", return_value=("linux", "Linux")):
            status = check_tools(attack=False)
        text = install_text(status)
        self.assertIn("sudo apt-get install -y", text)

    def test_install_text_mentions_windows_commands(self):
        with mock.patch("kali.preflight.which", return_value=None), \
             mock.patch("kali.preflight._detect_os", return_value=("windows", "Windows")):
            status = check_tools(attack=False)
        text = install_text(status)
        self.assertIn("Windows", text)
        # Sur Windows avec alternatives, on doit mentionner les alternatives
        self.assertIn("alternative", text.lower())

    def test_detect_os_returns_valid(self):
        os_id, os_name = _detect_os()
        self.assertIn(os_id, ("linux", "windows", "macos"))
        self.assertIsInstance(os_name, str)

    def test_windows_alternatives_defined(self):
        """Les alternatives Windows sont bien definies pour les outils cibles."""
        self.assertIn("nikto", _WINDOWS_ALTERNATIVES)
        self.assertIn("gobuster", _WINDOWS_ALTERNATIVES)
        self.assertIn("sslscan", _WINDOWS_ALTERNATIVES)
        self.assertEqual(_WINDOWS_ALTERNATIVES["nikto"], "whatweb")
        self.assertEqual(_WINDOWS_ALTERNATIVES["gobuster"], "dirsearch")
        self.assertEqual(_WINDOWS_ALTERNATIVES["sslscan"], "whatweb")


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

    def test_binary_field_exists(self):
        for name, spec in TOOLS.items():
            self.assertIn("bin", spec, f"{name} manque 'bin'")
            self.assertIsInstance(spec["bin"], str)

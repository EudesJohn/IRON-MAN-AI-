"""Tests du préflight WebScan Kali (présence des outils, commandes d'installation multi-OS)."""

import unittest
from unittest import mock

from kali.preflight import (
    check_tools, install_commands, missing_tools, install_text, _detect_os,
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
        with mock.patch("kali.preflight.shutil.which", return_value=None), \
             mock.patch("kali.preflight._detect_os", return_value=("linux", "Linux")):
            status = check_tools(attack=False)
            missing = missing_tools(status)
            self.assertEqual(len(missing), len(status))
            cmds = install_commands(missing)
            self.assertEqual(cmds[0], "sudo apt-get update")
            self.assertTrue(cmds[1].startswith("sudo apt-get install -y "))
            for _, info in missing:
                self.assertIn(info["apt"], cmds[1])

    def test_check_tools_with_all_missing_windows(self):
        with mock.patch("kali.preflight.shutil.which", return_value=None), \
             mock.patch("kali.preflight._detect_os", return_value=("windows", "Windows")), \
             mock.patch("kali.preflight.shutil.which", side_effect=lambda b: None):
            status = check_tools(attack=False)
        missing = missing_tools(status)
        self.assertEqual(len(missing), len(status))
        cmds = install_commands(missing)
        # Sur Windows, on doit avoir au moins une commande
        self.assertTrue(len(cmds) > 0)
        # Les commandes doivent être adaptées à Windows (pas de apt-get)
        for cmd in cmds:
            self.assertNotIn("apt-get", cmd)

    def test_check_tools_attack_gates_output(self):
        # Sans --attack, aucun outil invasif (sqlmap, xsstrike, commix, hydra).
        names_web = {name for name, _ in all_tools(attack=False)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertNotIn(invasive, names_web)
        names_attack = {name for name, _ in all_tools(attack=True)}
        for invasive in ("sqlmap", "xsstrike", "commix", "hydra"):
            self.assertIn(invasive, names_attack)

    def test_install_text_mentions_apt_package_linux(self):
        with mock.patch("kali.preflight.shutil.which", side_effect=lambda b: None), \
             mock.patch("kali.preflight._detect_os", return_value=("linux", "Linux")):
            status = check_tools(attack=False)
        text = install_text(status)
        self.assertIn("sudo apt-get install -y", text)
        # Chaque outil manquant a sa ligne  ->  sudo apt-get install -y <apt>
        for name, _ in missing_tools(status):
            self.assertIn(f"sudo apt-get install -y {TOOLS[name]['apt']}", text)

    def test_install_text_mentions_windows_commands(self):
        with mock.patch("kali.preflight.shutil.which", side_effect=lambda b: None), \
             mock.patch("kali.preflight._detect_os", return_value=("windows", "Windows")):
            status = check_tools(attack=False)
        text = install_text(status)
        self.assertIn("Windows", text)
        # Au moins une commande Windows (choco, winget, ou pip)
        has_windows_cmd = any(
            word in text for word in ["choco", "winget", "pip install"]
        )
        self.assertTrue(has_windows_cmd, f"Pas de commande Windows dans :\n{text}")

    def test_detect_os_returns_valid(self):
        os_id, os_name = _detect_os()
        self.assertIn(os_id, ("linux", "windows", "macos"))
        self.assertIsInstance(os_name, str)


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

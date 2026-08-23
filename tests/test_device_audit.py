"""Tests du module d'audit de périphérique Android (adb).

Simule les sorties adb (subprocess.run mocké) : aucun appareil réel
requis. Vérifie la découverte, les contrôles de posture, le score et
les exports JSON/HTML.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kali.device_audit import DeviceAuditor, DeviceAuditResult


# Sorties adb simulées : {commande -> stdout}
PROPS = {
    "ro.product.model": "Pixel 7",
    "ro.product.manufacturer": "Google",
    "ro.build.version.release": "14",
    "ro.build.version.sdk": "34",
    "ro.build.version.security_patch": "2024-03-05",
    "ro.build.type": "user",
    "ro.boot.verifiedbootstate": "green",
    "ro.crypto.state": "encrypted",
    "sys.oem_unlock_allowed": "0",
    "service.adb.tcp.port": "",
}


def fake_subprocess_run(cmd, capture_output=True, text=True, timeout=15):
    """Renvoie une sortie adb simulée selon la commande."""
    out = ""
    if cmd[:2] == ["adb", "devices"]:
        out = "List of devices attached\nZY1234\tdevice\n"
    elif cmd[:3] == ["adb", "-s", "ZY1234"] and cmd[3] == "shell":
        shell = " ".join(cmd[4:])
        if shell.startswith("getprop "):
            key = shell.split(" ", 1)[1].strip()
            out = PROPS.get(key, "")
        elif shell == "getenforce":
            out = "Enforcing"
        elif shell == "dumpsys lock_settings":
            out = "  lockscreen.password_type: 2\n"
        elif shell == "settings get global adb_enabled":
            out = "1"
        elif shell == "settings get global adb_port":
            out = "null"
        elif shell == "settings get secure mock_location":
            out = "0"
        elif shell == "settings get secure enabled_accessibility_services":
            out = "null"
        elif shell == "settings get secure install_non_market_apps":
            out = "0"
        elif shell == "settings get global package_verifier_enable":
            out = "1"
    return mock.Mock(returncode=0, stdout=out, stderr="")


class TestDeviceAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = DeviceAuditor()
        self.patcher = mock.patch.object(
            subprocess, "run", side_effect=fake_subprocess_run)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_list_devices(self):
        self.assertEqual(self.auditor.list_devices(), ["ZY1234"])

    def test_full_audit_ok_device(self):
        result = self.auditor.audit()
        self.assertIsInstance(result, DeviceAuditResult)
        self.assertEqual(result.info.model, "Pixel 7")
        self.assertEqual(result.info.manufacturer, "Google")
        self.assertEqual(result.info.android_version, "14")
        self.assertEqual(result.info.lock_type, "PIN")
        self.assertEqual(result.info.encrypted, "encrypted")
        self.assertEqual(result.info.selinux, "Enforcing")
        self.assertFalse(result.errors)
        # 10 contrôles
        self.assertEqual(len(result.checks), 10)
        statuses = {c.status for c in result.checks}
        # appareil sain : au pire des warn (débogage USB activé pour l'audit)
        self.assertIn("ok", statuses)
        # débogage USB = warn (activé pour l'audit, à désactiver ensuite)
        usb = next(c for c in result.checks if c.name == "Débogage USB")
        self.assertEqual(usb.status, "warn")
        # pas de critique sur un appareil sain
        self.assertNotIn("critical", statuses)

    def test_score(self):
        result = self.auditor.audit()
        # 1 warn (débogage USB) → 100 - 10 = 90
        self.assertEqual(result.score, 90)

    def test_no_lock_is_critical(self):
        def fake(cmd, **kw):
            r = fake_subprocess_run(cmd, **kw)
            if "dumpsys lock_settings" in " ".join(cmd):
                r.stdout = "  lockscreen.password_type: 0\n"
            return r
        with mock.patch.object(subprocess, "run", side_effect=fake):
            result = self.auditor.audit()
        lock = next(c for c in result.checks if c.name == "Verrou d'écran")
        self.assertEqual(lock.status, "critical")
        self.assertEqual(lock.value, "aucun")

    def test_unencrypted_is_critical(self):
        def fake(cmd, **kw):
            r = fake_subprocess_run(cmd, **kw)
            if "ro.crypto.state" in " ".join(cmd):
                r.stdout = "unencrypted\n"
            return r
        with mock.patch.object(subprocess, "run", side_effect=fake):
            result = self.auditor.audit()
        enc = next(c for c in result.checks if c.name == "Chiffrement du stockage")
        self.assertEqual(enc.status, "critical")
        self.assertEqual(result.score, 65)  # 90 - 25

    def test_adb_network_is_critical(self):
        def fake(cmd, **kw):
            r = fake_subprocess_run(cmd, **kw)
            if "service.adb.tcp.port" in " ".join(cmd):
                r.stdout = "5555\n"
            return r
        with mock.patch.object(subprocess, "run", side_effect=fake):
            result = self.auditor.audit()
        net = next(c for c in result.checks if c.name == "ADB réseau (adb tcpip)")
        self.assertEqual(net.status, "critical")
        self.assertEqual(net.value, "5555")

    def test_no_device_connected(self):
        def fake(cmd, **kw):
            r = fake_subprocess_run(cmd, **kw)
            if cmd[:2] == ["adb", "devices"]:
                r.stdout = "List of devices attached\n\n"
            return r
        with mock.patch.object(subprocess, "run", side_effect=fake):
            result = self.auditor.audit()
        self.assertTrue(result.errors)
        self.assertIn("Aucun appareil", result.errors[0])
        self.assertEqual(result.checks, [])

    def test_multiple_devices_requires_serial(self):
        def fake(cmd, **kw):
            r = fake_subprocess_run(cmd, **kw)
            if cmd[:2] == ["adb", "devices"]:
                r.stdout = ("List of devices attached\n"
                            "ZY1234\tdevice\nAB5678\tdevice\n")
            return r
        with mock.patch.object(subprocess, "run", side_effect=fake):
            result = self.auditor.audit()
        self.assertTrue(result.errors)
        self.assertIn("--serial", result.errors[0])

    def test_serial_explicit(self):
        result = self.auditor.audit(serial="ZY1234")
        self.assertEqual(result.info.serial, "ZY1234")
        self.assertFalse(result.errors)

    def test_exports_json_and_html(self):
        tmp = tempfile.mkdtemp(prefix="test_device_")
        try:
            result = self.auditor.audit()
            jp = os.path.join(tmp, "rapport.json")
            hp = os.path.join(tmp, "rapport.html")
            self.auditor.export_json(result, jp)
            self.auditor.export_html(result, hp)
            data = json.load(open(jp))
            self.assertEqual(data["info"]["model"], "Pixel 7")
            self.assertEqual(len(data["checks"]), 10)
            self.assertIn("Score de posture", open(hp).read())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

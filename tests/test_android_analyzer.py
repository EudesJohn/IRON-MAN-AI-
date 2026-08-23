"""Tests du module Android Analyzer (analyse statique d'APK).

Génère un APK minimal (manifeste AXML binaire + classes.dex factice) en
stdlib, puis vérifie le décodage AXML, l'extraction du manifeste, les
permissions/composants, les secrets et les findings. Aucun outil externe
(jadx, apktool) requis : les tests passent avec le fallback stdlib.
"""

import hashlib
import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

from kali.android_analyzer import (
    AndroidAnalyzer,
    AXMLParser,
    decode_axml,
    DANGEROUS_PERMISSIONS,
    HIGH_RISK_PERMISSIONS,
)

# ---------------------------------------------------------------------------
# Construction d'un APK de test (100 % stdlib)
# ---------------------------------------------------------------------------


def _u16(v):
    return struct.pack("<H", v)


def _u32(v):
    return struct.pack("<I", v)


def _build_string_pool(strings):
    """Construit le chunk string pool (UTF-8) d'un AXML."""
    header_size = 28
    data = bytearray()
    offsets = []
    for s in strings:
        b = s.encode("utf-8")
        offsets.append(len(data))
        if len(b) < 0x80:
            data += bytes([len(b)])
        else:
            data += bytes([((len(b) >> 8) & 0x7F) | 0x80, len(b) & 0xFF])
        data += b
    strings_start = header_size + 4 * len(strings)
    chunk_size = strings_start + len(data)
    chunk = _u16(0x0001) + _u16(header_size) + _u32(chunk_size)
    chunk += _u32(len(strings)) + _u32(0) + _u32(0x100)  # drapeau UTF-8
    chunk += _u32(strings_start) + _u32(0)               # stylesStart = 0
    for off in offsets:
        chunk += _u32(off)
    chunk += bytes(data)
    return chunk


def _attr(ns, name, raw, dtype, data):
    return (_u32(ns) + _u32(name) + _u32(raw)
            + _u16(8) + bytes([0]) + bytes([dtype]) + _u32(data))


def _start_element(line, name, attrs, idx):
    payload = _u32(line) + _u32(0) + _u32(0xFFFFFFFF) + _u32(idx[name])
    payload += (_u16(36) + _u16(20) + _u16(len(attrs))
                + _u16(0) + _u16(0) + _u16(0))
    body = b"".join(_attr(*a) for a in attrs)
    size = 16 + 20 + len(body)
    return _u16(0x0102) + _u16(36) + _u32(size) + payload + body


def _end_element(name, idx):
    payload = _u32(1) + _u32(0) + _u32(0xFFFFFFFF) + _u32(idx[name])
    return _u16(0x0103) + _u16(16) + _u32(24) + payload


def build_manifest_axml():
    """Manifeste AXML binaire minimal (UTF-8), comme produit par aapt."""
    strings = [
        "http://schemas.android.com/apk/res/android",      # 0
        "package", "com.example.testapp",                  # 1, 2
        "versionName", "1.0",                              # 3, 4
        "versionCode", "1",                                # 5, 6
        "uses-permission", "name",                         # 7, 8
        "android.permission.CAMERA",                       # 9
        "android.permission.INTERNET",                     # 10
        "application", "label", "TestApp",                 # 11, 12, 13
        "allowBackup", "true",                             # 14, 15
        "usesCleartextTraffic",                            # 16
        "activity", "com.example.testapp.MainActivity",    # 17, 18
        "exported",                                        # 19
        "manifest",                                        # 20
    ]
    idx = {s: i for i, s in enumerate(strings)}
    chunks = [_build_string_pool(strings)]
    chunks.append(_start_element(1, "manifest", [
        (0, 1, 0xFFFFFFFF, 0x03, idx["com.example.testapp"]),  # package
        (0, 3, 0xFFFFFFFF, 0x03, idx["1.0"]),                  # versionName
        (0, 5, 0xFFFFFFFF, 0x10, 1),                           # versionCode
    ], idx))
    chunks.append(_start_element(2, "uses-permission",
                                 [(0, 8, 0xFFFFFFFF, 0x03, idx["android.permission.CAMERA"])], idx))
    chunks.append(_end_element("uses-permission", idx))
    chunks.append(_start_element(2, "uses-permission",
                                 [(0, 8, 0xFFFFFFFF, 0x03, idx["android.permission.INTERNET"])], idx))
    chunks.append(_end_element("uses-permission", idx))
    chunks.append(_start_element(3, "application", [
        (0, 12, 0xFFFFFFFF, 0x03, idx["TestApp"]),
        (0, 14, 0xFFFFFFFF, 0x12, 1),  # allowBackup=true
        (0, 16, 0xFFFFFFFF, 0x12, 1),  # usesCleartextTraffic=true
    ], idx))
    chunks.append(_start_element(4, "activity", [
        (0, 8, 0xFFFFFFFF, 0x03, idx["com.example.testapp.MainActivity"]),
        (0, 19, 0xFFFFFFFF, 0x12, 1),  # exported=true
    ], idx))
    chunks.append(_end_element("activity", idx))
    chunks.append(_end_element("application", idx))
    chunks.append(_end_element("manifest", idx))
    body = b"".join(chunks)
    # En-tête XML racine du fichier AXML (type 0x0003, headerSize 8)
    return _u16(0x0003) + _u16(8) + _u32(len(body) + 8) + body


def build_test_apk(path, manifest=None, dex_strings=None):
    """Écrit un APK minimal (manifeste AXML + classes.dex) à `path`."""
    manifest = manifest if manifest is not None else build_manifest_axml()
    dex = b"dex\n035\x00" + (dex_strings or b"")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("resources.arsc", b"\x00" * 8)


def _uleb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_real_dex():
    """Construit un vrai classes.dex (format 035) : 4 méthodes retournent
    chacune une chaîne à risque, pour que jadx les expose dans le code
    décompilé. Vérifié avec jadx (checksum adler32 + signature sha1)."""
    strings = [
        "L",                                        # 0 shorty ()Ljava/lang/String;
        "Lcom/example/TestApp;",                    # 1
        "Ljava/lang/Object;",                       # 2
        "Ljava/lang/String;",                       # 3
        "a", "b", "c", "d",                         # 4-7 noms de méthodes
        "setJavaScriptEnabled(true)",               # 8
        "AKIA0123456789ABCDEF",                     # 9
        "https://api.example.com/login",            # 10
        'MessageDigest.getInstance("MD5")',         # 11
    ]
    string_data = [
        _uleb128(len(s)) + s.encode("utf-8") + b"\x00" for s in strings
    ]
    type_ids = [1, 2, 3]                 # TestApp, Object, String
    proto_ids = [(0, 2, 0)]              # shorty "L", retour String
    method_ids = [(0, 0, 4), (0, 0, 5), (0, 0, 6), (0, 0, 7)]  # a,b,c,d

    def make_code(string_idx):
        insns = _u16(0x011A) + _u16(string_idx)   # const-string v1, #idx
        insns += _u16(0x0111)                     # return-object v1
        return struct.pack("<HHHHII", 2, 1, 0, 0, 0, 3) + insns

    code_items = [make_code(i) for i in (8, 9, 10, 11)]

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(type_ids)
    field_ids_off = proto_ids_off + 12 * len(proto_ids)
    method_ids_off = field_ids_off
    class_defs_off = method_ids_off + 8 * len(method_ids)
    data_off = class_defs_off + 32  # 1 class_def

    data = bytearray()

    def add_section(blob):
        nonlocal data
        pad = (-len(data)) % 4
        data += b"\x00" * pad
        off = data_off + len(data)
        data += blob
        return off

    string_data_blob = b"".join(string_data)
    string_ids = [
        data_off + sum(len(d) for d in string_data[:i])
        for i in range(len(strings))
    ]

    # class_data : 0 static, 0 instance, 4 direct, 0 virtual
    # idx_diff (0,1,1,1) → index absolus 0..3 ; code_off >= 128 → 2 octets
    class_data_len = 4 + 4 * 4
    add_section(string_data_blob)
    pad = (-len(data)) % 4
    data += b"\x00" * pad
    class_data_off = data_off + len(data)
    data += b"\x00" * class_data_len
    code_offs = [add_section(c) for c in code_items]

    real = _uleb128(0) + _uleb128(0) + _uleb128(4) + _uleb128(0)
    for i, co in enumerate(code_offs):
        real += _uleb128([0, 1, 1, 1][i]) + _uleb128(0x1) + _uleb128(co)
    assert len(real) == class_data_len
    rel = class_data_off - data_off
    data[rel:rel + len(real)] = real

    class_defs_b = struct.pack("<IIIIIIII",
                               0, 0x1, 1, 0, 0xFFFFFFFF, 0,
                               class_data_off, 0)

    pad = (-len(data)) % 4
    data += b"\x00" * pad
    map_off = data_off + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_ids), type_ids_off),
        (0x0003, len(proto_ids), proto_ids_off),
        (0x0005, len(method_ids), method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2004, 1, class_data_off),
        (0x2005, len(code_items), code_offs[0]),
        (0x2006, len(strings), data_off),
        (0x2000, 1, map_off),
    ]
    map_blob = struct.pack("<I", len(map_items))
    for t, size, off in map_items:
        map_blob += struct.pack("<HHII", t, 0, size, off)
    data += map_blob

    header = b"dex\n035\x00" + b"\x00" * 24
    header += struct.pack("<I", data_off + len(data))  # file_size
    header += struct.pack("<I", header_size)
    header += struct.pack("<I", 0x12345678)
    header += struct.pack("<II", 0, 0)
    header += struct.pack("<I", map_off)
    header += struct.pack("<II", len(strings), string_ids_off)
    header += struct.pack("<II", len(type_ids), type_ids_off)
    header += struct.pack("<II", len(proto_ids), proto_ids_off)
    header += struct.pack("<II", 0, field_ids_off)
    header += struct.pack("<II", len(method_ids), method_ids_off)
    header += struct.pack("<II", 1, class_defs_off)
    header += struct.pack("<II", len(data), data_off)

    string_ids_b = b"".join(struct.pack("<I", off) for off in string_ids)
    type_ids_b = b"".join(struct.pack("<I", t) for t in type_ids)
    proto_ids_b = b"".join(struct.pack("<III", *p) for p in proto_ids)
    method_ids_b = b"".join(struct.pack("<HHI", *m) for m in method_ids)

    dex = bytearray(header + string_ids_b + type_ids_b + proto_ids_b
                    + method_ids_b + class_defs_b + bytes(data))
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    dex[8:12] = struct.pack("<I", zlib.adler32(bytes(dex[12:])))
    return bytes(dex)


# ---------------------------------------------------------------------------
# Parseur AXML
# ---------------------------------------------------------------------------


class TestAXMLParser(unittest.TestCase):
    def test_decode_manifest_structure(self):
        xml = decode_axml(build_manifest_axml())
        self.assertIn("<manifest", xml)
        self.assertIn("</manifest>", xml)
        self.assertIn("uses-permission", xml)
        self.assertIn("activity", xml)

    def test_decode_attributes_and_values(self):
        xml = decode_axml(build_manifest_axml())
        self.assertIn('android:package="com.example.testapp"', xml)
        self.assertIn('android:name="android.permission.CAMERA"', xml)
        self.assertIn('android:label="TestApp"', xml)
        self.assertIn('android:allowBackup="true"', xml)
        self.assertIn('android:exported="true"', xml)

    def test_decode_garbage_returns_empty(self):
        self.assertEqual(decode_axml(b"\x00\x01\x02not axml at all"), "")
        self.assertEqual(decode_axml(b""), "")

    def test_malformed_never_hangs(self):
        # chunk_size incohérent (0) : le parseur doit s'arrêter proprement
        data = _u16(0x0003) + _u16(8) + _u32(100)
        data += _u16(0x0001) + _u16(28) + _u32(0)  # taille 0 → chunk invalide
        xml = decode_axml(data)
        self.assertIsInstance(xml, str)


# ---------------------------------------------------------------------------
# Analyseur complet
# ---------------------------------------------------------------------------


class TestAndroidAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="test_android_")
        self.apk = os.path.join(self.tmp, "test_app.apk")
        build_test_apk(self.apk)
        self.analyzer = AndroidAnalyzer()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_info_extracted_from_binary_manifest(self):
        result = self.analyzer.analyze_apk(self.apk)
        self.assertEqual(result.info.package, "com.example.testapp")
        self.assertEqual(result.info.version_name, "1.0")
        self.assertEqual(result.info.version_code, "1")
        self.assertTrue(result.info.allow_backup)
        self.assertTrue(result.info.uses_cleartext)
        self.assertEqual(len(result.info.sha256), 64)

    def test_permissions_detected(self):
        result = self.analyzer.analyze_apk(self.apk)
        names = {p.name for p in result.permissions}
        self.assertIn("android.permission.CAMERA", names)
        self.assertIn("android.permission.INTERNET", names)
        cam = next(p for p in result.permissions
                   if p.name == "android.permission.CAMERA")
        self.assertTrue(cam.dangerous)

    def test_components_detected(self):
        result = self.analyzer.analyze_apk(self.apk)
        self.assertEqual(len(result.components), 1)
        comp = result.components[0]
        self.assertEqual(comp.kind, "activity")
        self.assertEqual(comp.name, "com.example.testapp.MainActivity")
        self.assertTrue(comp.exported)

    def test_manifest_findings(self):
        result = self.analyzer.analyze_apk(self.apk)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("android-allow-backup", rule_ids)
        self.assertIn("android-cleartext-traffic", rule_ids)
        self.assertIn("android-dangerous-permission", rule_ids)
        self.assertIn("android-exported-component", rule_ids)

    def test_secrets_and_risky_code_from_dex(self):
        dex = (b"AKIA0123456789ABCDEF "
               b"setJavaScriptEnabled(true) "
               b'MessageDigest.getInstance("MD5")')
        apk2 = os.path.join(self.tmp, "risky.apk")
        build_test_apk(apk2, dex_strings=dex)
        result = self.analyzer.analyze_apk(apk2)
        self.assertEqual(result.summary["secrets_found"], 1)
        self.assertIn("Clé AWS", result.secrets[0])
        labels = [f.title for f in result.findings
                  if f.rule_id == "android-risky-code"]
        self.assertTrue(any("WebView" in t for t in labels))
        self.assertTrue(any("hachage faible" in t for t in labels))

    def test_missing_file(self):
        result = self.analyzer.analyze_apk("/nonexistent/foo.apk")
        self.assertTrue(result.errors)

    def test_summary_shape(self):
        result = self.analyzer.analyze_apk(self.apk)
        s = result.summary
        self.assertIn("total_findings", s)
        self.assertIn("by_severity", s)
        self.assertIn("dangerous_permissions", s)
        self.assertEqual(s["dangerous_permissions"], 1)

    def test_permission_classifications(self):
        # Classification cohérente des listes de permissions
        self.assertIn("android.permission.QUERY_ALL_PACKAGES",
                      HIGH_RISK_PERMISSIONS)
        self.assertIn("android.permission.QUERY_ALL_PACKAGES",
                      DANGEROUS_PERMISSIONS)
        self.assertIn("android.permission.CAMERA", DANGEROUS_PERMISSIONS)
        # PACKAGE_USAGE_STATS est signature/protected : présent dans
        # HIGH_RISK mais pas dans DANGEROUS (c'est voulu)
        self.assertNotIn("android.permission.PACKAGE_USAGE_STATS",
                         DANGEROUS_PERMISSIONS)


@unittest.skipUnless(shutil.which("jadx"), "jadx non installé")
class TestJadxEnrichment(unittest.TestCase):
    """Enrichissement jadx : avec un dex réel, jadx décompile le code et
    l'analyseur détecte les patterns dans le code source Java."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="test_jadx_")
        self.apk = os.path.join(self.tmp, "real.apk")
        dex = build_real_dex()
        with zipfile.ZipFile(self.apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", build_manifest_axml())
            zf.writestr("classes.dex", dex)
            zf.writestr("resources.arsc", b"\x00" * 8)
        self.analyzer = AndroidAnalyzer()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_real_dex_is_decompilable(self):
        self.assertTrue(self.analyzer.tools.get("jadx"))

    def test_jadx_risky_code_findings(self):
        result = self.analyzer.analyze_apk(self.apk)
        jadx_findings = [f for f in result.findings
                         if f.rule_id == "android-jadx-risky-code"]
        self.assertTrue(jadx_findings,
                        "jadx devrait trouver des patterns dans le code "
                        "décompilé")
        titles = " ".join(f.title for f in jadx_findings)
        self.assertIn("WebView", titles)
        self.assertIn("hachage faible", titles)
        for f in jadx_findings:
            self.assertTrue(f.file.endswith(".java"), f.file)

    def test_base_analysis_still_works_with_real_dex(self):
        result = self.analyzer.analyze_apk(self.apk)
        self.assertEqual(result.summary["secrets_found"], 1)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("android-allow-backup", rule_ids)


class TestJadxPartialFailure(unittest.TestCase):
    """jadx renvoie 3 quand des classes échouent mais produit quand même
    une sortie exploitable — l'enrichissement ne doit pas être jeté."""

    def _make_apk(self):
        tmp = tempfile.mkdtemp(prefix="test_jadx_rc3_")
        apk = os.path.join(tmp, "app.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", build_manifest_axml())
            zf.writestr("classes.dex", b"dex\n035" + b"\x00" * 64)
            zf.writestr("resources.arsc", b"\x00" * 8)
        return tmp, apk

    def test_rc3_with_output_still_enriches(self):
        from unittest import mock
        import kali.android_analyzer as mod

        tmp, apk = self._make_apk()
        try:
            real_run = mod.subprocess.run

            def fake_run(cmd, **kwargs):
                if cmd and cmd[0] == "jadx":
                    # cmd = ["jadx", "-d", <tmp>, "--no-res", apk]
                    out_dir = cmd[cmd.index("-d") + 1]
                    src = os.path.join(out_dir, "sources", "com", "example")
                    os.makedirs(src)
                    with open(os.path.join(src, "Test.java"), "w") as f:
                        f.write('class Test { void run() {'
                                ' web.setJavaScriptEnabled(true); } }')
                    return mock.Mock(returncode=3)
                return real_run(cmd, **kwargs)

            analyzer = AndroidAnalyzer()
            with mock.patch.object(mod.subprocess, "run",
                                   side_effect=fake_run):
                result = analyzer.analyze_apk(apk)
            jadx = [f for f in result.findings
                    if f.rule_id == "android-jadx-risky-code"]
            self.assertTrue(jadx,
                            "rc=3 avec sortie doit quand même enrichir")
            self.assertTrue(
                any("WebView" in f.title for f in jadx))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

"""Module Android Analyzer — analyse statique de sécurité d'applications APK.

Analyse les fichiers APK (ou AAB) pour détecter les faiblesses de sécurité
courantes, sans décompiler entièrement l'application. L'analyse repose sur :

  1. Le manifeste Android (AndroidManifest.xml) : permissions, composants
     exportés, debuggable, backup autorisé, cleartext traffic…
  2. Les chaînes du bytecode (classes.dex) : secrets codés en dur, URLs
     sensibles, APIs dangereuses (WebView, crypto faible, SQL, téléphonie).
  3. La configuration : minSdk/targetSdk, signature, ressources.
  4. Optionnellement jadx/apktool s'ils sont installés (décompilation
     complète pour aller plus loin).

Usage :
    from kali.android_analyzer import AndroidAnalyzer
    analyzer = AndroidAnalyzer()
    result = analyzer.analyze_apk("app.apk")
    print(result.summary)
"""

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None

import struct


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AndroidFinding:
    """Un problème de sécurité détecté dans l'APK."""
    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    description: str = ""
    recommendation: str = ""
    snippet: str = ""
    file: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AndroidPermission:
    """Une permission demandée par l'application."""
    name: str
    protection: str = "normal"
    dangerous: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AndroidComponent:
    """Un composant Android (activity, service, receiver, provider)."""
    name: str
    kind: str
    exported: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AndroidApkInfo:
    """Informations de base sur l'APK."""
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: bool = False
    network_security: bool = False
    file_size: int = 0
    sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AndroidAnalysisResult:
    """Résultat complet de l'analyse d'un APK."""
    apk_path: str
    info: AndroidApkInfo = field(default_factory=AndroidApkInfo)
    permissions: List[AndroidPermission] = field(default_factory=list)
    components: List[AndroidComponent] = field(default_factory=list)
    findings: List[AndroidFinding] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "package": self.info.package,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "dangerous_permissions": sum(
                1 for p in self.permissions if p.dangerous
            ),
            "exported_components": sum(
                1 for c in self.components if c.exported
            ),
            "secrets_found": len(self.secrets),
        }

    def to_dict(self) -> dict:
        return {
            "apk_path": self.apk_path,
            "info": self.info.to_dict(),
            "permissions": [p.to_dict() for p in self.permissions],
            "components": [c.to_dict() for c in self.components],
            "findings": [f.to_dict() for f in self.findings],
            "secrets": self.secrets,
            "urls": self.urls,
            "errors": self.errors,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Parseur AXML (manifeste binaire Android) — 100 % stdlib
# ---------------------------------------------------------------------------

# Types de chunks AXML
_CHUNK_STRING_POOL = 0x0001
_CHUNK_XML_START_NS = 0x0100
_CHUNK_XML_END_NS = 0x0101
_CHUNK_XML_START_ELEMENT = 0x0102
_CHUNK_XML_END_ELEMENT = 0x0103
_CHUNK_XML_CDATA = 0x0104
_CHUNK_XML_RESOURCE_MAP = 0x0180
_CHUNK_XML_END = 0x0003

# Types de valeurs typées (Res_value)
_TYPED_STRING = 0x03
_TYPED_INT_DEC = 0x10
_TYPED_INT_HEX = 0x11
_TYPED_INT_BOOLEAN = 0x12

# Attributs connus du manifeste (namespace android:)
_NS_ANDROID = "http://schemas.android.com/apk/res/android"


class AXMLParser:
    """Décode un fichier AndroidManifest.xml binaire (AXML) en XML texte.

    Implémentation minimale des chunks nécessaires au manifeste :
    string pool (UTF-8/UTF-16), start/end element, attributs typés.
    Ne nécessite aucune dépendance externe.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.strings: List[str] = []
        self.ns_stack: List[str] = []
        self.out: List[str] = []
        self.indent = 0
        self._string_is_utf8 = False

    # --- Utilitaires -----------------------------------------------------

    def _u16(self) -> int:
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def _u32(self) -> int:
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def _skip(self, n: int):
        self.pos += n

    def _string(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""

    # --- String pool -----------------------------------------------------

    def _parse_string_pool(self):
        # parse() a déjà consommé l'en-tête de chunk (8 octets) :
        # on lit directement le payload de ResStringPool_header.
        string_count = self._u32()
        style_count = self._u32()
        flags = self._u32()
        strings_start = self._u32()
        styles_start = self._u32()
        self._string_is_utf8 = (flags & 0x100) != 0

        offsets = [self._u32() for _ in range(string_count)]
        if style_count:
            self._skip(4 * style_count)

        for off in offsets:
            # strings_start est relatif au début du chunk ; les offsets sont
            # relatifs au début des données de chaînes.
            base = self._chunk_start + strings_start + off
            self.strings.append(self._read_string(base))

        # Aller à la fin du chunk
        self.pos = self._chunk_end

    def _read_string(self, base: int) -> str:
        """Lit une chaîne du pool (UTF-8 ou UTF-16 selon le flag)."""
        save = self.pos
        self.pos = base
        try:
            if self._string_is_utf8:
                # u8len (1-2 octets)
                first = self.data[self.pos]
                self.pos += 1
                if first & 0x80:
                    second = self.data[self.pos]
                    self.pos += 1
                    length = ((first & 0x7F) << 8) | second
                else:
                    length = first
                raw = self.data[self.pos:self.pos + length]
                return raw.decode("utf-8", errors="replace")
            else:
                length = self._u16()
                raw = self.data[self.pos:self.pos + length * 2]
                return raw.decode("utf-16-le", errors="replace")
        finally:
            self.pos = save

    # --- Éléments ---------------------------------------------------------

    def _parse_start_element(self):
        # Payload de ResXMLTree_attrExt (en-tête de chunk déjà consommé).
        line = self._u32()
        comment = self._u32()
        ns_idx = self._u32()
        name_idx = self._u32()
        attr_start = self._u16()
        attr_size = self._u16()
        attr_count = self._u16()
        id_index = self._u16()
        class_index = self._u16()
        style_index = self._u16()

        ns = self._string(ns_idx)
        name = self._string(name_idx)

        # Attributs : (ns, name, raw_value, data_type, data).
        # attributeStart est relatif au début du chunk (ResXMLTree_node).
        attrs = []
        if attr_start:
            attr_pos = self._chunk_start + attr_start
        else:
            attr_pos = self.pos
        save = self.pos
        self.pos = attr_pos
        for _ in range(attr_count):
            a_ns = self._u32()
            a_name = self._u32()
            a_raw = self._u32()
            t_size = self._u16()
            t_res0 = self._u8()
            t_type = self._u8()
            t_data = self._u32()
            attrs.append((a_ns, a_name, a_raw, t_type, t_data))
        self.pos = save

        # Sérialiser en XML
        indent = "  " * self.indent
        parts = [f"{indent}<{name}"]
        if ns:
            parts[0] = f"{indent}<{ns.split('.')[-1]}:{name}"
        for a_ns, a_name, a_raw, t_type, t_data in attrs:
            aname = self._string(a_name)
            if not aname:
                continue
            prefix = ""
            # Dans les vrais manifests, l'URL du namespace android: est
            # souvent l'index 0 du pool : ne pas exclure a_ns == 0.
            if a_ns != 0xFFFFFFFF:
                ans = self._string(a_ns)
                if ans == _NS_ANDROID:
                    prefix = "android:"
            # Valeur : pour une chaîne, l'index est dans rawValue s'il est
            # présent, sinon dans typedValue.data (cas aapt courant).
            if t_type == _TYPED_STRING:
                sidx = a_raw if a_raw != 0xFFFFFFFF else t_data
                value = self._string(sidx).replace('"', '&quot;')
                parts.append(f' {prefix}{aname}="{value}"')
            elif t_type == _TYPED_INT_BOOLEAN:
                parts.append(f' {prefix}{aname}="{"true" if t_data else "false"}"')
            elif t_type in (_TYPED_INT_DEC, _TYPED_INT_HEX):
                parts.append(f' {prefix}{aname}="{t_data}"')
            elif t_type == 0x1C:  # TYPE_FLOAT
                import struct as _s
                parts.append(f' {prefix}{aname}="{_s.unpack("<f", _s.pack("<I", t_data))[0]:g}"')
            elif a_raw != 0xFFFFFFFF:
                value = self._string(a_raw).replace('"', '&quot;')
                parts.append(f' {prefix}{aname}="{value}"')
        parts.append(">")
        self.out.append("".join(parts))
        self.indent += 1

    def _parse_end_element(self):
        # Payload de ResXMLTree_endElementExt (en-tête déjà consommé).
        line = self._u32()
        comment = self._u32()
        ns_idx = self._u32()
        name_idx = self._u32()
        ns = self._string(ns_idx)
        name = self._string(name_idx)
        self.indent = max(0, self.indent - 1)
        indent = "  " * self.indent
        tag = f"{ns.split('.')[-1]}:{name}" if ns else name
        self.out.append(f"{indent}</{tag}>")

    def _parse_cdata(self):
        # Payload de ResXMLTree_cdataExt (en-tête déjà consommé).
        line = self._u32()
        comment = self._u32()
        data_idx = self._u32()
        t_size = self._u16()
        t_res0 = self._u8()
        t_type = self._u8()
        t_data = self._u32()
        text = self._string(data_idx)
        indent = "  " * self.indent
        self.out.append(f"{indent}{text}")

    # --- Parser principal -------------------------------------------------

    def _u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def parse(self) -> str:
        """Décode l'AXML et renvoie le XML texte."""
        # En-tête : type (u16), header_size (u16), taille totale (u32)
        total = struct.unpack_from("<I", self.data, 4)[0]
        self.pos = 8
        iters = 0
        while self.pos + 8 <= len(self.data) and self.pos < total:
            iters += 1
            # Garde anti-boucle : un AXML malformé ne doit jamais faire
            # boucler l'analyseur (chunk_size incohérent).
            if iters > 100000:
                break
            chunk_type = self._u16()
            header_size = self._u16()
            chunk_size = self._u32()
            self._chunk_start = self.pos - 8
            self._chunk_end = self.pos + (chunk_size - 8)
            if self._chunk_end <= self._chunk_start:
                # chunk invalide : on s'arrête proprement
                break

            if chunk_type == _CHUNK_STRING_POOL:
                self._parse_string_pool()
            elif chunk_type == _CHUNK_XML_START_ELEMENT:
                self._parse_start_element()
            elif chunk_type == _CHUNK_XML_END_ELEMENT:
                self._parse_end_element()
            elif chunk_type == _CHUNK_XML_START_NS:
                self._skip(8)  # ns (u32) + name (u32)
            elif chunk_type == _CHUNK_XML_END_NS:
                self._skip(4)  # ns (u32)
            elif chunk_type == _CHUNK_XML_CDATA:
                self._parse_cdata()
            else:
                self._skip(chunk_size - 8)

            # Se positionner au chunk suivant
            self.pos = self._chunk_end

        return "\n".join(self.out)


def decode_axml(data: bytes) -> str:
    """Décode un AndroidManifest.xml binaire en XML texte.

    Renvoie une chaîne vide si le décodage échoue (données non-AXML).
    """
    try:
        return AXMLParser(data).parse()
    except (struct.error, IndexError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Règles de détection
# ---------------------------------------------------------------------------

# Permissions dangereuses (protection level dangerous selon Android)
DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

# Permissions sensibles / à risque de détournement
HIGH_RISK_PERMISSIONS = {
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
}

# Patterns de secrets (regex sur les chaînes du dex)
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "Clé AWS Access Key ID"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Clé API Google"),
    (re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24}"), "Clé Stripe live"),
    (re.compile(r"pk_live_[0-9a-zA-Z]{24}"), "Clé publique Stripe live"),
    (re.compile(r"(?i)xox[baprs]-[0-9a-zA-Z-]{10,}"), "Token Slack"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "Token GitHub"),
    (re.compile(r"(?i)-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
     "Clé privée (PEM)"),
    (re.compile(r"(?i)(api[_-]?key|apikey|secret|password|passwd|token)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']"),
     "Secret codé en dur"),
    (re.compile(r"(?i)firebase[_-]?api[_-]?key\s*=\s*[\"'][^\"'\s]+[\"']"),
     "Clé Firebase"),
    (re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
     "Token FCM/legacy Firebase"),
]

# Patterns d'URLs / endpoints sensibles
URL_PATTERNS = [
    (re.compile(r"https?://[^\s\"'<>]+"), "URL HTTP(S)"),
]

# Patterns de code dangereux (dans les chaînes dex)
DANGEROUS_CODE_PATTERNS = [
    (re.compile(r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)"),
     "WebView avec JavaScript activé (risque XSS/injection)"),
    (re.compile(r"(?i)addJavascriptInterface"),
     "WebView addJavascriptInterface (risque RCE si mal configuré)"),
    (re.compile(r"(?i)setAllowFileAccess\s*\(\s*true\s*\)"),
     "WebView avec accès fichier activé"),
    (re.compile(r"(?i)loadUrl\s*\(\s*[\"']file://"),
     "WebView charge un fichier local (risque de fuite)"),
    (re.compile(r"(?i)\b(?:MD5|SHA-?1)\b"
                r"|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']"),
     "Algorithme de hachage faible (MD5/SHA-1)"),
    (re.compile(r"(?i)\b(?:3DES|DES)\b|\bRC4\b|AES/ECB"),
     "Chiffrement faible ou mode ECB"),
    (re.compile(r"(?i)SQLiteDatabase\.rawQuery|execSQL\s*\([^)]*[+]"),
     "Requête SQL concaténée (risque d'injection SQL)"),
    (re.compile(r"(?i)TrustManager.*X509TrustManager|setHostnameVerifier"),
     "Validation TLS désactivée (risque MITM)"),
    (re.compile(r"(?i)getDeviceId|getImei|Build\.SERIAL"),
     "Accès aux identifiants de l'appareil (vie privée)"),
    (re.compile(r"(?i)ClipboardManager|ClipData"),
     "Accès au presse-papiers (fuite de données possible)"),
    (re.compile(r"(?i)ClassLoader|loadClass\s*\([^)]*[\"']http"),
     "Chargement dynamique de code à distance (risque RCE)"),
    (re.compile(r"(?i)DexClassLoader|PathClassLoader"),
     "Chargement dynamique de code (décompilable, risque de détournement)"),
    (re.compile(r"(?i)SharedPreferences.*MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"),
     "SharedPreferences avec accès monde (Android 4.2-)"),
    (re.compile(r"(?i)setFlags\s*\(\s*FLAG_SECURE"),
     "Protection anti-capture d'écran (info)"),
]


# ---------------------------------------------------------------------------
# Android Analyzer
# ---------------------------------------------------------------------------

class AndroidAnalyzer:
    """Analyse statique de sécurité d'un fichier APK/AAB.

    L'analyse est entièrement locale et ne nécessite ni jadx ni apktool
    pour les contrôles de base (manifeste binaire décodé par les outils
    disponibles, chaînes dex). Si jadx est installé, une analyse
    complémentaire du code décompilé est réalisée.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._tools = self._check_tools()

    @staticmethod
    def _check_tools() -> Dict[str, bool]:
        """Vérifie la présence des outils Android disponibles."""
        return {
            "apktool": shutil.which("apktool") is not None,
            "jadx": shutil.which("jadx") is not None,
            "aapt": shutil.which("aapt") is not None or shutil.which("aapt2") is not None,
            "dex2jar": shutil.which("d2j-dex2jar") is not None,
            "zipalign": shutil.which("zipalign") is not None,
        }

    @property
    def tools(self) -> Dict[str, bool]:
        return dict(self._tools)

    # ------------------------------------------------------------------
    # Entrée principale
    # ------------------------------------------------------------------

    def analyze_apk(self, apk_path: str,
                    check_secrets: bool = True,
                    check_code: bool = True,
                    use_jadx: bool = True) -> AndroidAnalysisResult:
        """Analyse un fichier APK/AAB. Renvoie un AndroidAnalysisResult.

        use_jadx=False désactive la décompilation complète (jadx),
        très lente sur les grosses applications (~10 min).
        """
        result = AndroidAnalysisResult(apk_path=apk_path)

        if not os.path.exists(apk_path):
            result.errors.append(f"Fichier introuvable : {apk_path}")
            return result

        # Empreinte SHA-256
        try:
            result.info.sha256 = self._sha256(apk_path)
            result.info.file_size = os.path.getsize(apk_path)
        except OSError as exc:
            result.errors.append(f"Lecture fichier : {exc}")
            return result

        # Analyse du manifeste
        manifest = self._extract_manifest(apk_path)
        if manifest:
            self._analyze_manifest(manifest, result)
        else:
            result.errors.append(
                "AndroidManifest.xml non lisible (binaire). "
                "Installez apktool pour décoder le manifeste."
            )

        # Analyse du bytecode (chaînes dex)
        dex_strings = self._extract_dex_strings(apk_path)

        if check_secrets:
            for pattern, label in SECRET_PATTERNS:
                for match in pattern.finditer("\n".join(dex_strings)):
                    found = match.group(0)
                    if len(found) > 8:  # éviter les faux positifs triviaux
                        result.secrets.append(f"{label} : {found}")
                        result.findings.append(AndroidFinding(
                            rule_id="android-secret-hardcoded",
                            severity="high",
                            title=f"Secret probablement codé en dur : {label}",
                            description=(
                                f"Une chaîne ressemblant à {label} a été "
                                f"trouvée dans le bytecode de l'application."
                            ),
                            recommendation=(
                                "Ne jamais stocker de secrets dans le code. "
                                "Utiliser des services de configuration "
                                "sécurisés (Android Keystore, backend)."
                            ),
                            snippet=found[:200],
                            file="classes.dex",
                        ))

        if check_code:
            for pattern, label in DANGEROUS_CODE_PATTERNS:
                for match in pattern.finditer("\n".join(dex_strings)):
                    result.findings.append(AndroidFinding(
                        rule_id="android-risky-code",
                        severity=self._code_severity(label),
                        title=f"Code à risque : {label}",
                        description=(
                            f"Le motif « {label} » a été détecté dans le "
                            f"bytecode. Vérifier que l'usage est sécurisé."
                        ),
                        recommendation=self._code_recommendation(label),
                        snippet=match.group(0)[:200],
                        file="classes.dex",
                    ))

        # URLs
        for pattern, _ in URL_PATTERNS:
            for match in pattern.finditer("\n".join(dex_strings)):
                url = match.group(0)
                if url not in result.urls:
                    result.urls.append(url)

        # URLs HTTP en clair → finding
        http_urls = [u for u in result.urls if u.startswith("http://")]
        if http_urls and result.info.uses_cleartext:
            result.findings.append(AndroidFinding(
                rule_id="android-cleartext-http",
                severity="high",
                title="Trafic HTTP en clair autorisé",
                description=(
                    "L'application autorise le trafic en clair "
                    "(usesCleartextTraffic) et contient des URLs http://. "
                    "Les données transitent sans chiffrement."
                ),
                recommendation=(
                    "Désactiver usesCleartextTraffic et forcer HTTPS via "
                    "networkSecurityConfig."
                ),
                snippet=", ".join(http_urls[:5])[:200],
                file="AndroidManifest.xml",
            ))

        # Analyse complémentaire si jadx disponible (opt-in, très lente)
        if self._tools.get("jadx") and check_code and use_jadx:
            jadx_findings = self._analyze_with_jadx(apk_path, result)
            result.findings.extend(jadx_findings)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sha256(path: str) -> str:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _code_severity(label: str) -> str:
        """Sévérité par défaut selon le motif détecté."""
        high_keywords = [
            "TrustManager", "RCE", "injection SQL", "clef privée",
            "addJavascriptInterface", "TLS désactivée",
        ]
        if any(k in label for k in high_keywords):
            return "high"
        return "medium"

    @staticmethod
    def _code_recommendation(label: str) -> str:
        if "WebView" in label or "addJavascriptInterface" in label:
            return ("Désactiver JavaScript si non requis, ou restreindre "
                    "addJavascriptInterface aux versions 4.2+ avec @JavascriptInterface.")
        if "hachage faible" in label:
            return "Utiliser SHA-256 ou mieux (PBKDF2, bcrypt, Argon2)."
        if "Chiffrement faible" in label:
            return "Utiliser AES-GCM avec une clé gérée par Android Keystore."
        if "injection SQL" in label:
            return "Utiliser des requêtes paramétrées ou Room/ContentProvider."
        if "TLS désactivée" in label:
            return "Implémenter une validation TLS stricte (certificat épinglé)."
        if "identifiants" in label:
            return "Limiter l'accès aux identifiants ; préférer un identifiant aléatoire."
        if "presse-papiers" in label:
            return "Ne pas copier de données sensibles dans le presse-papiers."
        if "RCE" in label or "chargement dynamique" in label:
            return "Éviter le chargement de code à distance ; signer et vérifier le code chargé."
        return "Revoir l'usage du motif concerné et appliquer les bonnes pratiques Android."

    # ------------------------------------------------------------------
    # Manifeste
    # ------------------------------------------------------------------

    def _extract_manifest(self, apk_path: str) -> Optional[str]:
        """Extrait AndroidManifest.xml (texte). Décode le binaire si apktool."""
        # Essayer apktool (décode le manifeste binaire)
        if self._tools.get("apktool"):
            tmp = tempfile.mkdtemp(prefix="android_manifest_")
            try:
                proc = subprocess.run(
                    ["apktool", "d", "-f", "-s", apk_path, "-o", tmp],
                    capture_output=True, text=True, timeout=120,
                )
                manifest_path = os.path.join(tmp, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    with open(manifest_path, "r", encoding="utf-8",
                              errors="replace") as f:
                        return f.read()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            finally:
                import shutil as _sh
                _sh.rmtree(tmp, ignore_errors=True)

        # Fallback : décodage AXML du manifeste binaire (100 % stdlib)
        try:
            with zipfile.ZipFile(apk_path) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    data = zf.read("AndroidManifest.xml")
                    decoded = decode_axml(data)
                    if decoded:
                        return decoded
                    # Dernier recours : chaînes lisibles brutes
                    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
                    return "\n".join(
                        s.decode("ascii", errors="replace")
                        for s in strings
                    )
        except (zipfile.BadZipFile, KeyError):
            pass
        return None

    def _analyze_manifest(self, manifest: str,
                          result: AndroidAnalysisResult):
        """Analyse le contenu (XML ou chaînes) du manifeste."""
        text = manifest

        # Package et versions (attributs du manifeste)
        pkg = re.search(r'package\s*=\s*"([^"]+)"', text)
        if pkg:
            result.info.package = pkg.group(1)

        vname = re.search(r'versionName\s*=\s*"([^"]+)"', text)
        if vname:
            result.info.version_name = vname.group(1)
        vcode = re.search(r'versionCode\s*=\s*"([^"]+)"', text)
        if vcode:
            result.info.version_code = vcode.group(1)

        min_sdk = re.search(r'minSdkVersion\s*=\s*"(\d+)"', text)
        if min_sdk:
            result.info.min_sdk = min_sdk.group(1)
        target_sdk = re.search(r'targetSdkVersion\s*=\s*"(\d+)"', text)
        if target_sdk:
            result.info.target_sdk = target_sdk.group(1)

        # Debuggable
        result.info.debuggable = 'android:debuggable="true"' in text
        # Backup
        backup_m = re.search(r'android:allowBackup\s*=\s*"(\w+)"', text)
        if backup_m:
            result.info.allow_backup = backup_m.group(1) == "true"
        # Cleartext
        result.info.uses_cleartext = (
            'android:usesCleartextTraffic="true"' in text
        )
        result.info.network_security = (
            "android:networkSecurityConfig" in text
        )

        # Permissions
        for perm in re.finditer(r'uses-permission[^>]*android:name\s*=\s*"([^"]+)"',
                                text):
            name = perm.group(1)
            result.permissions.append(AndroidPermission(
                name=name,
                dangerous=name in DANGEROUS_PERMISSIONS,
            ))

        # Composants
        for kind, tag in (("activity", "activity"), ("service", "service"),
                          ("receiver", "receiver"), ("provider", "provider")):
            for comp in re.finditer(
                    rf'<{tag}[^>]*android:name\s*=\s*"([^"]+)"[^>]*>', text):
                block_start = max(0, comp.start() - 200)
                block_end = min(len(text), comp.end() + 200)
                block = text[block_start:block_end]
                exported = (
                    'android:exported="true"' in block or
                    (tag == "provider" and "android:exported" not in block
                     and "android:grantUriPermissions" not in block)
                )
                result.components.append(AndroidComponent(
                    name=comp.group(1), kind=kind, exported=exported
                ))

        # Findings sur le manifeste
        if result.info.debuggable:
            result.findings.append(AndroidFinding(
                rule_id="android-debuggable",
                severity="high",
                title="Application debuggable",
                description=(
                    "android:debuggable=\"true\" permet de se connecter "
                    "via adb et d'extraire les données de l'application."
                ),
                recommendation=(
                    "Passer android:debuggable=\"false\" en production "
                    "(ou ne pas le définir du tout)."
                ),
                file="AndroidManifest.xml",
            ))

        if result.info.allow_backup:
            result.findings.append(AndroidFinding(
                rule_id="android-allow-backup",
                severity="medium",
                title="Sauvegarde de l'application autorisée",
                description=(
                    "android:allowBackup=\"true\" permet d'extraire les "
                    "données de l'application via adb backup."
                ),
                recommendation=(
                    "Mettre android:allowBackup=\"false\" si l'application "
                    "contient des données sensibles."
                ),
                file="AndroidManifest.xml",
            ))

        if result.info.uses_cleartext:
            result.findings.append(AndroidFinding(
                rule_id="android-cleartext-traffic",
                severity="high",
                title="Trafic en clair autorisé",
                description=(
                    "android:usesCleartextTraffic=\"true\" autorise le "
                    "HTTP en clair : interception possible des données."
                ),
                recommendation=(
                    "Désactiver le trafic en clair (défaut depuis "
                    "Android 9) ou configurer networkSecurityConfig."
                ),
                file="AndroidManifest.xml",
            ))

        # minSdk trop bas
        if result.info.min_sdk and result.info.min_sdk.isdigit():
            if int(result.info.min_sdk) < 21:
                result.findings.append(AndroidFinding(
                    rule_id="android-min-sdk-old",
                    severity="medium",
                    title=f"minSdkVersion bas ({result.info.min_sdk})",
                    description=(
                        "Un minSdkVersion inférieur à 21 expose "
                        "l'application à des failles corrigées dans les "
                        "versions récentes d'Android."
                    ),
                    recommendation=(
                        "Relever minSdkVersion à 21+ (Android 5.0) minimum."
                    ),
                    file="AndroidManifest.xml",
                ))

        # Permissions dangereuses
        for perm in result.permissions:
            if perm.name in HIGH_RISK_PERMISSIONS:
                result.findings.append(AndroidFinding(
                    rule_id="android-high-risk-permission",
                    severity="high",
                    title=f"Permission à haut risque : {perm.name.split('.')[-1]}",
                    description=(
                        f"La permission {perm.name} est à haut risque "
                        f"de détournement ou de collecte de données."
                    ),
                    recommendation=(
                        "Vérifier que la permission est indispensable et "
                        "obtenir le consentement explicite de l'utilisateur."
                    ),
                    snippet=perm.name,
                    file="AndroidManifest.xml",
                ))
            elif perm.dangerous:
                result.findings.append(AndroidFinding(
                    rule_id="android-dangerous-permission",
                    severity="low",
                    title=f"Permission dangereuse : {perm.name.split('.')[-1]}",
                    description=(
                        f"La permission {perm.name} donne accès à des "
                        f"données sensibles de l'utilisateur."
                    ),
                    recommendation=(
                        "Vérifier que la permission est nécessaire et "
                        "l'expliquer à l'utilisateur (privacy policy)."
                    ),
                    snippet=perm.name,
                    file="AndroidManifest.xml",
                ))

        # Composants exportés
        for comp in result.components:
            if comp.exported:
                result.findings.append(AndroidFinding(
                    rule_id="android-exported-component",
                    severity="medium" if comp.kind == "provider" else "low",
                    title=f"Composant exporté : {comp.name.split('.')[-1]}",
                    description=(
                        f"Le {comp.kind} {comp.name} est exporté : d'autres "
                        f"applications peuvent l'invoquer."
                    ),
                    recommendation=(
                        "Limiter l'export aux composants réellement "
                        "interopérables, avec permissions et vérification "
                        "de l'appelant (signature)."
                    ),
                    snippet=comp.name,
                    file="AndroidManifest.xml",
                ))

    # ------------------------------------------------------------------
    # Bytecode dex
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_dex_strings(apk_path: str) -> List[str]:
        """Extrait les chaînes UTF-8 des fichiers classes*.dex de l'APK."""
        strings = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if not re.match(r"classes\d*\.dex$", name):
                        continue
                    data = zf.read(name)
                    strings.extend(
                        s.decode("utf-8", errors="replace")
                        for s in re.findall(rb"[\x20-\x7e]{6,}", data)
                    )
        except (zipfile.BadZipFile, KeyError, OSError):
            pass
        return strings

    # ------------------------------------------------------------------
    # Analyse jadx complémentaire
    # ------------------------------------------------------------------

    def _analyze_with_jadx(self, apk_path: str,
                           result: AndroidAnalysisResult) -> List[AndroidFinding]:
        """Analyse complémentaire via jadx (décompilation complète)."""
        findings = []
        tmp = tempfile.mkdtemp(prefix="android_jadx_")
        try:
            proc = subprocess.run(
                ["jadx", "-d", tmp, "--no-res", apk_path],
                capture_output=True, text=True, timeout=900,
            )
            # jadx renvoie 3 quand des classes échouent (fréquent sur les
            # apps réelles : références non résolues, obfuscation…), tout en
            # produisant une sortie exploitable. Seul un échec total (autre
            # code) fait abandonner l'enrichissement.
            if proc.returncode not in (0, 3):
                result.errors.append(
                    "jadx a échoué (code "
                    + str(proc.returncode) + ") — enrichissement ignoré."
                )
                return findings

            # Chercher les patterns dangereux dans le code Java décompilé
            for root, _, files in os.walk(tmp):
                for fname in files:
                    if not fname.endswith(".java"):
                        continue
                    path = os.path.join(root, fname)
                    try:
                        with open(path, "r", encoding="utf-8",
                                  errors="replace") as f:
                            content = f.read()
                    except OSError:
                        continue
                    for pattern, label in DANGEROUS_CODE_PATTERNS:
                        matches = list(pattern.finditer(content))
                        if not matches:
                            continue
                        # Un finding par (règle × fichier) avec comptage :
                        # évite d'inonder le rapport (librairies, doublons).
                        first = matches[0]
                        rel = os.path.relpath(path, tmp)
                        findings.append(AndroidFinding(
                            rule_id="android-jadx-risky-code",
                            severity=self._code_severity(label),
                            title=f"Code à risque (jadx) : {label}",
                            description=(
                                f"Détecté dans {rel} "
                                f"(ligne {content[:first.start()].count(chr(10)) + 1}, "
                                f"{len(matches)} occurrence(s))."
                            ),
                            recommendation=self._code_recommendation(label),
                            snippet=first.group(0)[:200],
                            file=rel,
                        ))
        except subprocess.TimeoutExpired:
            result.errors.append(
                "jadx a dépassé 900 s — enrichissement ignoré "
                "(app trop grosse ou machine chargée)."
            )
        except FileNotFoundError:
            pass
        finally:
            import shutil as _sh
            _sh.rmtree(tmp, ignore_errors=True)
        return findings

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, result: AndroidAnalysisResult, path: str):
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

    def export_html(self, result: AndroidAnalysisResult, path: str):
        """Exporte le résultat en HTML (rapport lisible)."""
        data = result.to_dict()
        info = data["info"]

        findings_html = ""
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(data["findings"], key=lambda x: sev_order.get(x["severity"], 9)):
            color = {
                "critical": "#e74c3c", "high": "#ff6b6b",
                "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6",
            }.get(f["severity"], "#95a5a6")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}">
                <span class="sev" style="background:{color}">{f['severity'].upper()}</span>
                <strong>{f['title']}</strong>
                <div class="desc">{f['description']}</div>
                <div class="rec"><em>Recommandation :</em> {f['recommendation']}</div>
                {f'<code class="snippet">{f["snippet"]}</code>' if f['snippet'] else ''}
            </div>"""

        perms_html = "\n".join(
            f"<li>{p['name']} {'⚠️' if p['dangerous'] else ''}</li>"
            for p in data["permissions"]
        )
        comps_html = "\n".join(
            f"<li>{c['kind']} : <code>{c['name']}</code> "
            f"{'🔓 exporté' if c['exported'] else ''}</li>"
            for c in data["components"]
        )
        secrets_html = "\n".join(
            f"<li><code>{s}</code></li>" for s in data["secrets"]
        )
        urls_html = "\n".join(
            f"<li><code>{u}</code></li>" for u in data["urls"][:30]
        )
        summary = data["summary"]

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Android Analyzer — {info['package'] or os.path.basename(data['apk_path'])}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 1000px; margin: 40px auto; padding: 0 20px;
       background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }}
h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
h2 {{ color: #ff6b6b; margin-top: 30px; }}
.finding {{ background: #16213e; padding: 15px; margin: 12px 0; border-radius: 6px; }}
.sev {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
        color: white; font-size: 0.8em; font-weight: bold; margin-right: 8px; }}
.desc {{ margin: 8px 0; color: #b0b0b0; }}
.rec {{ color: #f39c12; font-size: 0.9em; }}
.snippet {{ display: block; margin-top: 8px; background: #0f0f1e;
             padding: 8px; border-radius: 4px; font-size: 0.85em;
             word-break: break-all; color: #2ecc71; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th {{ background: #16213e; color: #00d4ff; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #333; }}
code {{ background: #16213e; padding: 2px 6px; border-radius: 3px;
        word-break: break-all; }}
.info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
.info-grid div {{ background: #16213e; padding: 10px; border-radius: 6px; }}
ul {{ line-height: 1.8; }}
</style>
</head>
<body>
<h1>📱 Android Analyzer — Rapport de sécurité</h1>
<p><strong>APK :</strong> <code>{data['apk_path']}</code></p>

<h2>ℹ️ Informations</h2>
<div class="info-grid">
    <div><strong>Package :</strong> {info['package'] or 'N/A'}</div>
    <div><strong>Version :</strong> {info['version_name']} (code {info['version_code'] or 'N/A'})</div>
    <div><strong>minSdk :</strong> {info['min_sdk'] or 'N/A'}</div>
    <div><strong>targetSdk :</strong> {info['target_sdk'] or 'N/A'}</div>
    <div><strong>Debuggable :</strong> {'✅' if info['debuggable'] else '❌'}</div>
    <div><strong>Backup :</strong> {'⚠️ autorisé' if info['allow_backup'] else '✅ désactivé'}</div>
    <div><strong>Cleartext :</strong> {'⚠️ autorisé' if info['uses_cleartext'] else '✅ interdit'}</div>
    <div><strong>Taille :</strong> {info['file_size'] / 1024 / 1024:.1f} Mo</div>
    <div><strong>SHA-256 :</strong> <code>{info['sha256'][:16]}…</code></div>
</div>

<h2>📊 Résumé</h2>
<table>
<tr><th>Findings</th><th>Critiques</th><th>Hautes</th><th>Moyennes</th><th>Basses</th></tr>
<tr>
    <td>{summary['total_findings']}</td>
    <td>{summary['by_severity'].get('critical', 0)}</td>
    <td>{summary['by_severity'].get('high', 0)}</td>
    <td>{summary['by_severity'].get('medium', 0)}</td>
    <td>{summary['by_severity'].get('low', 0)}</td>
</tr>
</table>

<h2>🔍 Findings ({len(data['findings'])})</h2>
{findings_html or '<p><em>Aucun problème détecté.</em></p>'}

<h2>🔑 Secrets détectés ({len(data['secrets'])})</h2>
<ul>{secrets_html or '<li><em>Aucun secret détecté.</em></li>'}</ul>

<h2>🔓 Permissions ({len(data['permissions'])})</h2>
<ul>{perms_html or '<li><em>Aucune permission.</em></li>'}</ul>

<h2>🧩 Composants ({len(data['components'])})</h2>
<ul>{comps_html or '<li><em>Aucun composant.</em></li>'}</ul>

<h2>🌐 URLs détectées ({len(data['urls'])})</h2>
<ul>{urls_html or '<li><em>Aucune URL.</em></li>'}</ul>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

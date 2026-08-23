"""Audit de posture de sécurité d'un périphérique Android via adb.

Teste la RÉSISTANCE au déverrouillage et à la compromission d'appareils
que vous possédez (ou que vous êtes autorisé à auditer) : type de verrou,
chiffrement, débogage USB, adb réseau, OEM unlock, FRP, SELinux, services
d'accessibilité… Toutes les commandes sont en LECTURE SEULE (aucune
modification de l'appareil).

Cadre d'utilisation :
  - Appareil branché en USB avec le débogage USB activé (réglage qui
    nécessite l'accès à l'écran de l'appareil, donc son propriétaire).
  - `--authorized` obligatoire : votre matériel ou un client mandaté.
"""

from dataclasses import dataclass, field, asdict
import os
import subprocess
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """Informations de base sur le périphérique audité."""
    serial: str = ""
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    sdk: str = ""
    security_patch: str = ""
    build_type: str = ""          # user | userdebug | eng
    verified_boot: str = ""       # green | orange | red
    selinux: str = ""             # Enforcing | Permissive
    lock_type: str = ""           # none | PIN | mot de passe | schéma
    encrypted: str = ""           # encrypted | unencrypted

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceCheck:
    """Un contrôle de posture avec son verdict."""
    name: str
    status: str                   # ok | warn | critical | info
    value: str = ""
    detail: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceAuditResult:
    """Résultat complet de l'audit d'un périphérique."""
    info: DeviceInfo = field(default_factory=DeviceInfo)
    checks: List[DeviceCheck] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Note /100 : 100 - (critical*25 + warn*10), bornée à 0."""
        crit = sum(1 for c in self.checks if c.status == "critical")
        warn = sum(1 for c in self.checks if c.status == "warn")
        return max(0, 100 - crit * 25 - warn * 10)

    @property
    def summary(self) -> dict:
        by_status = {}
        for c in self.checks:
            by_status[c.status] = by_status.get(c.status, 0) + 1
        return {
            "device": self.info.model or self.info.serial,
            "score": self.score,
            "by_status": by_status,
            "total_checks": len(self.checks),
        }

    def to_dict(self) -> dict:
        return {
            "info": self.info.to_dict(),
            "checks": [c.to_dict() for c in self.checks],
            "errors": self.errors,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Audit via adb
# ---------------------------------------------------------------------------

class DeviceAuditor:
    """Exécute les contrôles de posture via `adb` (lecture seule)."""

    def __init__(self, adb: str = "adb"):
        self.adb = adb
        self.serial: Optional[str] = None

    # --- exécution --------------------------------------------------------

    def _run(self, args: List[str], timeout: int = 15) -> str:
        """Exécute `adb [-s serial] args` et renvoie stdout (texte)."""
        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += args
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode != 0:
                return ""
            return proc.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _shell(self, command: str, timeout: int = 15) -> str:
        return self._run(["shell", command], timeout=timeout).strip()

    def _getprop(self, key: str) -> str:
        return self._shell(f"getprop {key}", timeout=10).strip()

    # --- découverte -------------------------------------------------------

    def list_devices(self) -> List[str]:
        """Renvoie la liste des sérials d'appareils connectés (adb devices)."""
        out = self._run(["devices"])
        serials = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials

    # --- informations -----------------------------------------------------

    def collect_info(self) -> DeviceInfo:
        info = DeviceInfo(serial=self.serial or "")
        info.model = self._getprop("ro.product.model")
        info.manufacturer = self._getprop("ro.product.manufacturer")
        info.android_version = self._getprop("ro.build.version.release")
        info.sdk = self._getprop("ro.build.version.sdk")
        info.security_patch = self._getprop("ro.build.version.security_patch")
        info.build_type = self._getprop("ro.build.type")
        info.verified_boot = self._getprop("ro.boot.verifiedbootstate")
        info.selinux = self._shell("getenforce")
        info.encrypted = self._getprop("ro.crypto.state")
        info.lock_type = self._detect_lock_type()
        return info

    def _detect_lock_type(self) -> str:
        """Détermine le type de verrou d'écran (lecture seule)."""
        out = self._shell("dumpsys lock_settings", timeout=20)
        pw = ""
        for line in out.splitlines():
            # format réel : "lockscreen.password_type: 2" (ou "= 2")
            if "lockscreen.password_type" in line \
                    and "_quality" not in line:
                for sep in ("=", ":"):
                    if sep in line:
                        pw = line.split(sep, 1)[1].strip()
                        break
                if pw:
                    break
        pw = pw.strip()
        # Types Android : 0 = aucun, 1 = schéma, 2 = PIN, 3 = mot de passe
        mapping = {"0": "aucun", "1": "schéma", "2": "PIN", "3": "mot de passe"}
        if pw.isdigit() and pw in mapping:
            return mapping[pw]
        if "none" in pw.lower():
            return "aucun"
        return pw or "inconnu"

    # --- contrôles --------------------------------------------------------

    def _check_lock(self, info: DeviceInfo, checks: List[DeviceCheck]):
        if info.lock_type == "aucun":
            checks.append(DeviceCheck(
                name="Verrou d'écran",
                status="critical",
                value="aucun",
                detail="Aucun verrou d'écran : n'importe qui peut ouvrir "
                       "l'appareil et accéder aux données.",
                recommendation="Activer un verrou (PIN/schéma/mot de passe) "
                               "dans Paramètres > Sécurité.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Verrou d'écran",
                status="ok",
                value=info.lock_type,
                detail="Un verrou est actif.",
                recommendation="Utiliser un mot de passe fort et "
                               "l'authentification biométrique en complément.",
            ))

    def _check_encryption(self, info: DeviceInfo, checks: List[DeviceCheck]):
        if info.encrypted == "unencrypted":
            checks.append(DeviceCheck(
                name="Chiffrement du stockage",
                status="critical",
                value="non chiffré",
                detail="Les données sont lisibles sans clé (vol de "
                       "l'appareil = vol des données).",
                recommendation="Chiffrer l'appareil (Paramètres > Sécurité) "
                               "ou réinitialiser avec chiffrement forcé.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Chiffrement du stockage",
                status="ok",
                value=info.encrypted or "inconnu",
                detail="Le stockage est chiffré.",
            ))

    def _check_usb_debugging(self, checks: List[DeviceCheck]):
        val = self._shell("settings get global adb_enabled")
        if val.strip() == "1":
            checks.append(DeviceCheck(
                name="Débogage USB",
                status="warn",
                value="activé",
                detail="Le débogage USB est activé : un ordinateur de "
                       "confiance peut exécuter des commandes (c'est le "
                       "canal utilisé pour cet audit).",
                recommendation="Désactiver le débogage USB hors usage, "
                               "et révoquer les ordinateurs de confiance.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Débogage USB",
                status="ok",
                value="désactivé",
                detail="Le débogage USB est désactivé.",
            ))

    def _check_adb_network(self, checks: List[DeviceCheck]):
        # adb réseau : service.adb.tcp.port (1 = port 5555) ou adb_port
        port = self._getprop("service.adb.tcp.port")
        if not port:
            port = self._shell("settings get global adb_port")
        port = port.strip()
        if port and port != "null" and port != "0":
            checks.append(DeviceCheck(
                name="ADB réseau (adb tcpip)",
                status="critical",
                value=port,
                detail="L'appareil écoute ADB sur le réseau : toute personne "
                       "du réseau peut tenter de s'y connecter sans câble.",
                recommendation="Désactiver adb tcpip (adb usb) et le port "
                               "ADB réseau dans les réglages développeur.",
            ))
        else:
            checks.append(DeviceCheck(
                name="ADB réseau (adb tcpip)",
                status="ok",
                value="désactivé",
                detail="ADB n'écoute pas sur le réseau.",
            ))

    def _check_oem_unlock(self, info: DeviceInfo, checks: List[DeviceCheck]):
        oem = self._getprop("sys.oem_unlock_allowed")
        boot = (info.verified_boot or "").lower()
        if boot in ("orange", "red") or oem.strip() == "1":
            checks.append(DeviceCheck(
                name="Bootloader / OEM unlock",
                status="warn",
                value=boot or oem,
                detail="Bootloader déverrouillé (ou déverrouillage autorisé) : "
                       "permet d'installer un firmware modifié et facilite "
                       "la réinstallation du système.",
                recommendation="Re-verrouiller le bootloader "
                               "(fastboot oem lock) si le téléphone n'est "
                               "pas destiné aux ROM customs.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Bootloader / OEM unlock",
                status="ok",
                value=boot or "verrouillé",
                detail="Le bootloader est verrouillé (état vert).",
            ))

    def _check_selinux(self, info: DeviceInfo, checks: List[DeviceCheck]):
        if info.selinux and info.selinux.lower() != "enforcing":
            checks.append(DeviceCheck(
                name="SELinux",
                status="critical",
                value=info.selinux,
                detail="SELinux n'est pas en mode Enforcing : isolation "
                       "affaiblie entre applications et système.",
                recommendation="Rétablir SELinux Enforcing (setenforce 1 "
                               "ou ROM sécurisée).",
            ))
        else:
            checks.append(DeviceCheck(
                name="SELinux",
                status="ok",
                value=info.selinux or "inconnu",
                detail="SELinux applique les politiques de sécurité.",
            ))

    def _check_build_type(self, info: DeviceInfo, checks: List[DeviceCheck]):
        if info.build_type in ("userdebug", "eng"):
            checks.append(DeviceCheck(
                name="Type de build",
                status="warn",
                value=info.build_type,
                detail="Build de développement (userdebug/eng) : accès root "
                       "et adb root possibles, protections affaiblies.",
                recommendation="Utiliser une build de production (user) "
                               "sur un appareil quotidien.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Type de build",
                status="ok",
                value=info.build_type or "inconnu",
                detail="Build de production.",
            ))

    def _check_mock_locations(self, checks: List[DeviceCheck]):
        val = self._shell("settings get secure mock_location")
        if val.strip() == "1":
            checks.append(DeviceCheck(
                name="Fausses positions (mock location)",
                status="critical",
                value="activé",
                detail="La position GPS peut être falsifiée par une "
                       "application (géofencing, tracking contournés).",
                recommendation="Désactiver « Emplacement simulé » dans les "
                               "options développeur.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Fausses positions (mock location)",
                status="ok",
                value="désactivé",
                detail="Les positions simulées sont désactivées.",
            ))

    def _check_accessibility(self, checks: List[DeviceCheck]):
        val = self._shell(
            "settings get secure enabled_accessibility_services")
        val = val.strip()
        if val and val != "null":
            checks.append(DeviceCheck(
                name="Services d'accessibilité",
                status="warn",
                value="actifs",
                detail=f"Services actifs : {val[:120]} — les services "
                       "d'accessibilité peuvent lire l'écran et les "
                       "frappes ; n'en garder que de fiables.",
                recommendation="Vérifier la liste des services "
                               "d'accessibilité et supprimer les inconnus.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Services d'accessibilité",
                status="ok",
                value="aucun",
                detail="Aucun service d'accessibilité actif.",
            ))

    def _check_unknown_sources(self, checks: List[DeviceCheck]):
        # Android moderne : installations hors Play gérées par app ;
        # le flag historique install_non_market_apps reste indicatif.
        val = self._shell("settings get secure install_non_market_apps")
        verifier = self._shell("settings get global package_verifier_enable")
        if val.strip() == "1":
            checks.append(DeviceCheck(
                name="Sources inconnues",
                status="warn",
                value="autorisées",
                detail="L'installation d'applications hors Play Store est "
                       "autorisée globalement (risque de sideload malveillant).",
                recommendation="N'installer que des APK de confiance ; "
                               "vérifier les sources par application.",
            ))
        elif verifier.strip() == "0":
            checks.append(DeviceCheck(
                name="Vérification des applications",
                status="warn",
                value="désactivée",
                detail="La vérification des applications (Play Protect) "
                       "est désactivée.",
                recommendation="Réactiver la vérification des applications.",
            ))
        else:
            checks.append(DeviceCheck(
                name="Sources inconnues",
                status="ok",
                value="restreintes",
                detail="Les installations hors Play Store sont restreintes "
                       "et la vérification est active.",
            ))

    # --- flux principal ---------------------------------------------------

    def audit(self, serial: Optional[str] = None) -> DeviceAuditResult:
        """Audite un appareil connecté. Renvoie DeviceAuditResult."""
        result = DeviceAuditResult()
        if not serial:
            serials = self.list_devices()
            if not serials:
                result.errors.append(
                    "Aucun appareil connecté en mode débogage USB. "
                    "Branchez l'appareil, acceptez l'invite de confiance "
                    "et activez le débogage USB."
                )
                return result
            if len(serials) > 1:
                result.errors.append(
                    "Plusieurs appareils connectés : précisez --serial "
                    + ", ".join(serials)
                )
                return result
            serial = serials[0]
        self.serial = serial

        info = self.collect_info()
        result.info = info

        checks = []
        self._check_lock(info, checks)
        self._check_encryption(info, checks)
        self._check_usb_debugging(checks)
        self._check_adb_network(checks)
        self._check_oem_unlock(info, checks)
        self._check_selinux(info, checks)
        self._check_build_type(info, checks)
        self._check_mock_locations(checks)
        self._check_accessibility(checks)
        self._check_unknown_sources(checks)
        result.checks = checks
        return result

    # --- exports ----------------------------------------------------------

    def export_json(self, result: DeviceAuditResult, path: str):
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

    def export_html(self, result: DeviceAuditResult, path: str):
        """Exporte le résultat en HTML (rapport lisible)."""
        data = result.to_dict()
        info = data["info"]
        summary = data["summary"]
        badge = {
            "critical": ("#e74c3c", "CRITIQUE"),
            "warn": ("#f39c12", "ATTENTION"),
            "ok": ("#2ecc71", "OK"),
            "info": ("#95a5a6", "INFO"),
        }
        checks_html = ""
        order = {"critical": 0, "warn": 1, "ok": 2, "info": 3}
        for c in sorted(data["checks"], key=lambda x: order.get(x["status"], 9)):
            color, label = badge.get(c["status"], ("#95a5a6", "INFO"))
            checks_html += f"""
            <div class="check" style="border-left: 4px solid {color}">
                <span class="sev" style="background:{color}">{label}</span>
                <strong>{c['name']}</strong>
                <span class="val">{c['value']}</span>
                <div class="desc">{c['detail']}</div>
                <div class="rec"><em>Recommandation :</em> {c['recommendation']}</div>
            </div>"""

        score_color = "#2ecc71" if summary["score"] >= 70 else \
            ("#f39c12" if summary["score"] >= 40 else "#e74c3c")

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Audit de périphérique — {info['model'] or info['serial']}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 1000px; margin: 40px auto; padding: 0 20px;
       background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }}
h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
h2 {{ color: #ff6b6b; margin-top: 30px; }}
.check {{ background: #16213e; padding: 15px; margin: 12px 0; border-radius: 6px; }}
.sev {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
        color: white; font-size: 0.8em; font-weight: bold; margin-right: 8px; }}
.val {{ color: #00d4ff; margin-left: 8px; }}
.desc {{ margin: 8px 0; color: #b0b0b0; }}
.rec {{ color: #f39c12; font-size: 0.9em; }}
.score {{ font-size: 3em; font-weight: bold; color: {score_color}; }}
.info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
.info-grid div {{ background: #16213e; padding: 10px; border-radius: 6px; }}
code {{ background: #16213e; padding: 2px 6px; border-radius: 3px; }}
ul {{ line-height: 1.8; }}
</style>
</head>
<body>
<h1>📱 Audit de périphérique Android</h1>
<p><strong>Appareil :</strong> {info['model'] or 'N/A'}
   ({info['manufacturer'] or 'N/A'}) — {info['serial']}</p>

<h2>ℹ️ Informations</h2>
<div class="info-grid">
    <div><strong>Android :</strong> {info['android_version'] or 'N/A'} (SDK {info['sdk'] or 'N/A'})</div>
    <div><strong>Correctif :</strong> {info['security_patch'] or 'N/A'}</div>
    <div><strong>Build :</strong> {info['build_type'] or 'N/A'}</div>
    <div><strong>Boot vérifié :</strong> {info['verified_boot'] or 'N/A'}</div>
    <div><strong>Verrou :</strong> {info['lock_type'] or 'N/A'}</div>
    <div><strong>Chiffrement :</strong> {info['encrypted'] or 'N/A'}</div>
    <div><strong>SELinux :</strong> {info['selinux'] or 'N/A'}</div>
</div>

<h2>📊 Score de posture</h2>
<p><span class="score">{summary['score']}</span>/100
   ({summary['total_checks']} contrôles :
   {summary['by_status'].get('critical', 0)} critiques,
   {summary['by_status'].get('warn', 0)} avertissements)</p>

<h2>🔍 Contrôles</h2>
{checks_html}

<p style="margin-top:30px; color:#95a5a6; font-size:0.85em">
Audit en lecture seule via adb — appareils que vous possédez ou êtes
autorisé à tester.</p>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)


# ---------------------------------------------------------------------------
# CLI minimal autonome (python -m kali.device_audit)
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="Audit de périphérique Android",
        description="Audit de posture d'un appareil Android via adb "
                    "(lecture seule, appareils autorisés).")
    parser.add_argument("--serial", help="Serial de l'appareil (auto si seul).")
    parser.add_argument("-o", "--output", help="Rapport (.json ou .html).")
    parser.add_argument("--authorized", action="store_true", required=True,
                        help="Confirme que l'appareil est le vôtre ou "
                             "autorisé (obligatoire).")
    args = parser.parse_args(argv)

    auditor = DeviceAuditor()
    result = auditor.audit(args.serial)
    if result.errors:
        for e in result.errors:
            print(f"[ERREUR] {e}")
        return 1

    info = result.info
    print("═" * 62)
    print("  Audit de périphérique Android")
    print("═" * 62)
    print(f"  Appareil  : {info.model or 'N/A'} ({info.manufacturer or 'N/A'})")
    print(f"  Android   : {info.android_version or 'N/A'} "
          f"(SDK {info.sdk or 'N/A'}) — correctif {info.security_patch or 'N/A'}")
    print(f"  Verrou    : {info.lock_type} | Chiffrement : "
          f"{info.encrypted or 'N/A'} | SELinux : {info.selinux or 'N/A'}")
    print()
    print(f"  Score de posture : {result.score}/100")
    for c in result.checks:
        mark = {"critical": "🔴", "warn": "🟠", "ok": "🟢", "info": "⚪"}[c.status]
        print(f"    {mark} {c.name:<30} {c.value}")
    print("═" * 62)

    if args.output:
        base = os.path.splitext(args.output)[0]
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".html":
            auditor.export_html(result, args.output)
            print(f"[device] Rapport HTML écrit : {args.output}")
        elif ext == ".json":
            auditor.export_json(result, args.output)
            print(f"[device] Rapport JSON écrit : {args.output}")
        else:
            auditor.export_json(result, base + ".json")
            auditor.export_html(result, base + ".html")
            print(f"[device] Rapports écrits : {base}.json / {base}.html")

    crit = sum(1 for c in result.checks if c.status == "critical")
    return 1 if crit else 0


if __name__ == "__main__":
    raise SystemExit(main())

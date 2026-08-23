"""IRON MAN AI — Modules WiFi, Android & périphériques : audit sécurité.

Trois modes complémentaires, dans un cadre **autorisé uniquement** :

  --wifi     Audit de sécurité d'un réseau WiFi que vous possédez :
             scan des réseaux, capture handshake WPA2, crack du mot de
             passe (dictionnaire), audit WPS, recommandations.
  --android  Analyse statique de sécurité d'un fichier APK/AAB :
             manifeste (permissions, composants exportés, debuggable…),
             secrets codés en dur, code à risque (WebView, crypto faible,
             SQL, TLS…), URLs, rapport HTML/JSON.
  --device   Audit de posture d'un appareil Android branché (adb) :
             verrou d'écran, chiffrement, débogage USB, adb réseau,
             bootloader, SELinux — lecture seule, appareils possédés.

Tous les modes exigent la confirmation --authorized (cibles que vous
possédez ou pour lesquelles vous avez une autorisation écrite).

Exemples :
    python mobile_scan.py --check
    python mobile_scan.py --wifi --interface wlan0 --authorized
    python mobile_scan.py --wifi --bssid AA:BB:CC:DD:EE:FF --crack \\
        --wordlist /usr/share/wordlists/rockyou.txt --authorized
    python mobile_scan.py --android app.apk --authorized
    python mobile_scan.py --android app.apk --authorized -o rapport.html
    python mobile_scan.py --device --authorized
    python mobile_scan.py --device --serial ZY12345678 --authorized -o rapport
"""

import argparse
import json
import os
import sys

from kali import __version__
from kali.android_analyzer import AndroidAnalyzer
from kali.device_audit import DeviceAuditor
from kali.wifi_pentest import WiFiPentest
from reports import timestamped_path


def _default_output(prefix: str) -> str:
    """Chemin de rapport par défaut (sans extension) : JSON + HTML
    sont écrits dans le dossier central `rapports/` (horodatés)."""
    return timestamped_path(prefix, "")


def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _banner(module: str) -> None:
    print(_color("1;36", "═" * 62))
    print(_color("1;36", f"  IRON MAN AI — {module}"))
    print(_color("1;36", "═" * 62))


# ---------------------------------------------------------------------------
# Mode WiFi
# ---------------------------------------------------------------------------

def _run_wifi(args) -> int:
    """Orchestre l'audit WiFi (réseau possédé / autorisé)."""
    tools = WiFiPentest.check_tools()
    print()
    print("[IRON MAN AI] Outils WiFi disponibles :")
    for name, present in tools.items():
        mark = _color("1;32", "[OK]") if present else _color("1;31", "[MANQUANT]")
        print(f"  {mark} {name}")

    essential = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    missing = [t for t in essential if not tools.get(t)]
    if missing and not args.allow_missing:
        _banner("WiFi")
        print("[ERREUR] Outils essentiels manquants : " + ", ".join(missing))
        print("  Installez : sudo apt-get install -y aircrack-ng")
        print("  (ou ajoutez --allow-missing pour continuer sans eux)")
        return 2
    if args.check:
        print("[IRON MAN AI] Vérification terminée — aucun audit lancé.")
        return 1 if missing else 0

    _banner("Audit WiFi")
    print(f"  Interface : {args.interface}")
    if args.bssid:
        print(f"  Cible     : {args.bssid}"
              + (f" ({args.ssid})" if args.ssid else ""))
    print()

    # --- Dry-run -----------------------------------------------------------
    if args.dry_run:
        print("[IRON MAN AI] Mode simulation (--dry-run) : aucune commande "
              "exécutée.")
        print("[IRON MAN AI] Étapes prévues :")
        print("  1. airmon-ng check kill && airmon-ng start " + args.interface)
        print(f"  2. airodump-ng --write <tmp>/scan --output-format csv "
              f"<mon_iface>  ({args.scan_time}s)")
        if args.bssid:
            print(f"  3. airodump-ng --bssid {args.bssid} --write "
                  f"<tmp>/handshake <mon_iface>")
            print("  4. aireplay-ng --deauth 5 --wait-for-client -a "
                  f"{args.bssid} <mon_iface>")
            if args.crack:
                print(f"  5. aircrack-ng -w {args.wordlist or '<wordlist>'} "
                      f"-b {args.bssid} <handshake>.cap")
            if args.wps:
                print(f"  6. reaver -i <mon_iface> -b {args.bssid} -vv")
        return 0

    pentest = WiFiPentest(interface=args.interface, verbose=args.verbose)

    try:
        # Mode monitor
        try:
            mon = pentest.enable_monitor_mode()
            print(f"[wifi] Interface monitor : {mon}")
        except Exception as exc:
            print(f"[ERREUR] Activation du mode monitor impossible : {exc}",
                  file=sys.stderr)
            print("  Vérifiez que vous êtes root et que l'interface est "
                  "compatible (iw list).", file=sys.stderr)
            return 1

        # Scan des réseaux
        print(f"[wifi] Scan des réseaux pendant {args.scan_time}s "
              "(Ctrl+C pour couper court)…")
        networks = pentest.scan_networks(duration=args.scan_time)
        print(f"[wifi] {len(networks)} réseau(x) détecté(s) :")
        for i, net in enumerate(networks[:20], 1):
            wps = " [WPS]" if net.wps else ""
            print(f"  {i:>2}. {net.ssid or '<caché>':<28} "
                  f"{net.bssid}  ch {net.channel:<3} "
                  f"{net.signal} dBm  {net.encryption}{wps}")

        if not args.bssid:
            print()
            print("[wifi] Aucune cible --bssid : arrêt après le scan. "
                  "Relancez avec --bssid <BSSID> pour capturer/cracker.")
            print("[wifi] Exemple : python mobile_scan.py --wifi "
                  "--bssid AA:BB:CC:DD:EE:FF --crack --authorized")
            pentest.disable_monitor_mode()
            return 0

        # Capture handshake + crack
        handshake = None
        if args.crack:
            print(f"[wifi] Capture du handshake de {args.bssid} "
                  f"({args.capture_time}s)…")
            handshake = pentest.capture_handshake(
                bssid=args.bssid, ssid=args.ssid, channel=args.channel,
                duration=args.capture_time,
            )
            if handshake.success:
                print(f"[wifi] ✅ Handshake capturé : {handshake.file_path} "
                      f"({handshake.packets} paquets)")
                print(f"[wifi] Crack avec {args.method}…")
                result = pentest.crack_wpa2(
                    handshake_path=handshake.file_path,
                    bssid=args.bssid, ssid=args.ssid,
                    wordlist=args.wordlist, method=args.method,
                )
                if result.found:
                    print(_color("1;32", f"[wifi] 🎉 MOT DE PASSE TROUVÉ : "
                                         f"{result.password}"))
                else:
                    print(f"[wifi] Mot de passe non trouvé "
                          f"({result.error or 'wordlist épuisée'})")
            else:
                print(f"[wifi] ❌ Capture échouée : {handshake.error}")
                print("  Astuce : relancez avec un client connecté, ou "
                      "augmentez --capture-time.")

        # Audit WPS
        wps_result = None
        if args.wps:
            print(f"[wifi] Audit WPS de {args.bssid} (reaver)…")
            wps_result = pentest.audit_wps(bssid=args.bssid,
                                           channel=args.channel)
            if wps_result.get("vulnerable"):
                print(_color("1;31",
                             f"[wifi] ⚠️ WPS VULNÉRABLE — PIN : "
                             f"{wps_result.get('pin', 'N/A')}"))
            else:
                print(f"[wifi] WPS non vulnérable "
                      f"({wps_result.get('error', 'pin non trouvé')})")

        # Rapport consolidé : on construit un objet résultat à la main.
        from kali.wifi_pentest import WiFiAuditResult
        report = WiFiAuditResult(interface=args.interface)
        report.networks = networks
        report.handshake = handshake
        if handshake and handshake.success:
            cr = pentest.crack_wpa2(
                handshake_path=handshake.file_path, bssid=args.bssid,
                ssid=args.ssid, wordlist=args.wordlist, method=args.method,
            )
            report.crack_results.append(cr)
        if wps_result:
            report.wps_results.append(wps_result)
        report.recommendations = pentest.generate_recommendations(report)

        print()
        print(_color("1;36", "═" * 62))
        print(_color("1;36", "  Recommandations de sécurité"))
        print(_color("1;36", "═" * 62))
        for i, rec in enumerate(report.recommendations, 1):
            print(f"  {i}. {rec}")

        # Rapports (par défaut : dossier central rapports/, horodaté)
        output = args.output or _default_output("wifi")
        base = os.path.splitext(output)[0]
        ext = os.path.splitext(output)[1].lower()
        try:
            if ext == ".json":
                pentest.export_json(report, output)
                print(f"[wifi] Rapport JSON écrit : {output}")
            elif ext == ".html":
                pentest.export_html(report, output)
                print(f"[wifi] Rapport HTML écrit : {output}")
            else:
                pentest.export_json(report, base + ".json")
                pentest.export_html(report, base + ".html")
                print(f"[wifi] Rapports écrits : {base}.json / {base}.html")
        except OSError as exc:
            print(f"[ERREUR] Écriture du rapport : {exc}", file=sys.stderr)
            return 1
    finally:
        pentest.disable_monitor_mode()
        print("[wifi] Interface restaurée.")

    return 0


# ---------------------------------------------------------------------------
# Mode Android
# ---------------------------------------------------------------------------

def _run_android(args) -> int:
    """Orchestre l'analyse statique d'un APK/AAB."""
    analyzer = AndroidAnalyzer(verbose=args.verbose)
    tools = analyzer.tools

    print()
    print("[IRON MAN AI] Outils Android disponibles :")
    for name, present in tools.items():
        mark = _color("1;32", "[OK]") if present else _color("1;31", "[MANQUANT]")
        note = "" if present else {
            "apktool": " (sudo apt-get install -y apktool)",
            "jadx": " (sudo apt-get install -y jadx)",
            "aapt": " (sudo apt-get install -y aapt)",
            "dex2jar": " (sudo apt-get install -y dex2jar)",
            "zipalign": " (sudo apt-get install -y zipalign)",
        }.get(name, "")
        print(f"  {mark} {name}{note}")
    print("  → L'analyse de base (manifeste, dex, secrets) fonctionne "
          "sans ces outils ; apktool enrichit le manifeste, et jadx "
          "(avec --jadx) décompile le code (~10 min sur les grosses apps).")

    if args.check:
        print("[IRON MAN AI] Vérification terminée — aucune analyse lancée.")
        return 0

    if not args.apk:
        print("[ERREUR] Indiquez un fichier APK : --apk <fichier.apk>.",
              file=sys.stderr)
        return 2

    if not os.path.exists(args.apk):
        print(f"[ERREUR] Fichier introuvable : {args.apk}", file=sys.stderr)
        return 1

    _banner("Analyse Android")
    print(f"  APK : {args.apk}")
    print()

    # --- Dry-run -----------------------------------------------------------
    if args.dry_run:
        print("[IRON MAN AI] Mode simulation (--dry-run) : aucune analyse "
              "lancée.")
        print("[IRON MAN AI] Étapes prévues :")
        print(f"  1. Extraction de l'empreinte SHA-256 de {args.apk}")
        print("  2. Analyse d'AndroidManifest.xml (permissions, composants, "
              "debuggable…)")
        print("  3. Extraction des chaînes classes*.dex (secrets, code à "
              "risque, URLs)")
        if tools.get("apktool"):
            print("  4. apktool d -f -s <apk> (décodage du manifeste binaire)")
        if tools.get("jadx") and args.jadx:
            print("  5. jadx -d <tmp> --no-res <apk> (décompilation "
                  "complémentaire, --jadx)")
        print(f"  6. Rapport {'JSON/HTML' if args.output else 'console'}")
        return 0

    if tools.get("jadx") and args.jadx and not args.no_code:
        print(_color("0;33", "[IRON MAN AI] jadx : décompilation en cours… "
                              "(10+ minutes sur les grosses apps)"))

    result = analyzer.analyze_apk(
        args.apk,
        check_secrets=not args.no_secrets,
        check_code=not args.no_code,
        use_jadx=args.jadx,
    )

    # Résumé console
    s = result.summary
    print(_color("1;36", "═" * 62))
    print(_color("1;36", "  IRON MAN AI — Résumé de l'analyse Android"))
    print(_color("1;36", "═" * 62))
    print(f"  Package           : {result.info.package or 'N/A'}")
    print(f"  Version           : {result.info.version_name or 'N/A'}"
          + (f" (code {result.info.version_code})" if result.info.version_code else ""))
    print(f"  minSdk/targetSdk  : {result.info.min_sdk or 'N/A'} / "
          f"{result.info.target_sdk or 'N/A'}")
    print(f"  SHA-256           : {result.info.sha256[:16]}…")
    print()
    print(f"  Total findings    : {s['total_findings']}")
    by_sev = s["by_severity"]
    for sev in ("critical", "high", "medium", "low"):
        n = by_sev.get(sev, 0)
        bar = "█" * min(n, 30) or "·"
        color = {"critical": "1;31", "high": "1;33",
                 "medium": "0;33", "low": "0;36"}[sev]
        print(f"    {_color(color, sev.ljust(8))} {n:<4d} {bar}")
    print(f"  Permissions dangereuses : {s['dangerous_permissions']}")
    print(f"  Composants exportés     : {s['exported_components']}")
    print(f"  Secrets détectés        : {s['secrets_found']}")

    if args.verbose or not args.output:
        print()
        print("  Détail des findings :")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(result.findings, key=lambda x: order.get(x.severity, 9)):
            color = {"critical": "1;31", "high": "1;33",
                     "medium": "0;33", "low": "0;36", "info": "0;37"}[f.severity]
            print(f"    {_color(color, f.severity.ljust(8))} "
                  f"{f.rule_id:<35} {f.title[:55]}")
        if result.secrets:
            print()
            print("  Secrets :")
            for sec in result.secrets[:10]:
                print(f"    ⚠️  {sec[:100]}")
        if result.urls:
            print()
            print(f"  URLs ({len(result.urls)}) :")
            for u in result.urls[:10]:
                print(f"    {u[:100]}")

    for err in result.errors:
        print(_color("1;31", f"  [AVERTISSEMENT] {err}"))

    print(_color("1;36", "═" * 62))

    # Rapports (par défaut : dossier central rapports/, horodaté)
    output = args.output or _default_output("android")
    base = os.path.splitext(output)[0]
    ext = os.path.splitext(output)[1].lower()
    try:
        if ext == ".html":
            analyzer.export_html(result, output)
            print(f"[android] Rapport HTML écrit : {output}")
        elif ext == ".json":
            analyzer.export_json(result, output)
            print(f"[android] Rapport JSON écrit : {output}")
        else:
            analyzer.export_json(result, base + ".json")
            analyzer.export_html(result, base + ".html")
            print(f"[android] Rapports écrits : {base}.json / {base}.html")
    except OSError as exc:
        print(f"[ERREUR] Écriture du rapport : {exc}", file=sys.stderr)
        return 1

    return 1 if by_sev.get("critical") or by_sev.get("high") else 0


# ---------------------------------------------------------------------------
# Mode Périphérique (adb — appareils possédés)
# ---------------------------------------------------------------------------

def _run_device(args) -> int:
    """Audit de posture d'un appareil Android branché (adb, lecture seule)."""
    # Vérification adb
    adb_path = None
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, "adb")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            adb_path = cand
            break
    print()
    if not adb_path:
        print(_color("1;31", "  [MANQUANT] adb — installez android-tools-adb "
                              "(sudo apt-get install -y adb)"))
        print("  → L'audit de périphérique nécessite adb et un appareil "
              "branché avec débogage USB.")
        if args.check:
            print("[IRON MAN AI] Vérification terminée — aucune analyse lancée.")
            return 0
        return 1
    print(_color("1;32", "  [OK] adb"))

    if args.check:
        print("[IRON MAN AI] Vérification terminée — aucune analyse lancée.")
        return 0

    _banner("Audit de périphérique Android")

    # Dry-run
    if args.dry_run:
        print("[IRON MAN AI] Mode simulation (--dry-run) : aucune commande "
              "exécutée sur l'appareil.")
        print("[IRON MAN AI] Étapes prévues (lecture seule via adb) :")
        print("  1. adb devices (découverte de l'appareil)")
        print("  2. getprop : modèle, Android, correctif, build, bootloader")
        print("  3. dumpsys lock_settings (type de verrou d'écran)")
        print("  4. settings get : débogage USB, adb réseau, mock location,"
              "     accessibilité, sources inconnues")
        print("  5. getenforce (SELinux) + ro.crypto.state (chiffrement)")
        print(f"  6. Rapport {'JSON/HTML' if args.output else 'console'}")
        return 0

    auditor = DeviceAuditor()
    result = auditor.audit(args.serial)

    for err in result.errors:
        print(_color("1;31", f"  [ERREUR] {err}"))
        return 1

    info = result.info
    print(_color("1;36", "═" * 62))
    print(_color("1;36", "  IRON MAN AI — Résumé de l'audit"))
    print(_color("1;36", "═" * 62))
    print(f"  Appareil  : {info.model or 'N/A'} "
          f"({info.manufacturer or 'N/A'})")
    print(f"  Android   : {info.android_version or 'N/A'} "
          f"(SDK {info.sdk or 'N/A'}) — correctif "
          f"{info.security_patch or 'N/A'}")
    print(f"  Verrou    : {info.lock_type} | Chiffrement : "
          f"{info.encrypted or 'N/A'} | SELinux : {info.selinux or 'N/A'}")
    print()
    print(f"  Score de posture : {result.score}/100")
    for c in result.checks:
        mark = {"critical": "🔴", "warn": "🟠",
                "ok": "🟢", "info": "⚪"}[c.status]
        print(f"    {mark} {_color('1;37', c.name):<30} {c.value}")
    print(_color("1;36", "═" * 62))

    # Rapports (par défaut : dossier central rapports/, horodaté)
    output = args.output or _default_output("device")
    base = os.path.splitext(output)[0]
    ext = os.path.splitext(output)[1].lower()
    try:
        if ext == ".html":
            auditor.export_html(result, output)
            print(f"[device] Rapport HTML écrit : {output}")
        elif ext == ".json":
            auditor.export_json(result, output)
            print(f"[device] Rapport JSON écrit : {output}")
        else:
            auditor.export_json(result, base + ".json")
            auditor.export_html(result, base + ".html")
            print(f"[device] Rapports écrits : {base}.json / {base}.html")
        except OSError as exc:
            print(f"[ERREUR] Écriture du rapport : {exc}", file=sys.stderr)
            return 1

    crit = sum(1 for c in result.checks if c.status == "critical")
    return 1 if crit else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur CLI des modes WiFi, Android & périphériques."""
    parser = argparse.ArgumentParser(
        prog="IRON MAN AI (WiFi, Android & périphériques)",
        description=("Audit de sécurité réseau WiFi, analyse statique "
                     "d'applications Android et audit de périphérique "
                     "(adb) — cadre autorisé uniquement."),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--check", "--preflight", action="store_true",
                        help="Vérifie les outils disponibles, sans audit.")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirme que vous êtes autorisé à tester "
                             "(obligatoire).")
    parser.add_argument("--allow-missing", action="store_true",
                        help="Continue même si des outils manquent.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Affiche les étapes sans rien exécuter.")
    parser.add_argument("-o", "--output", metavar="FICHIER",
                        help="Rapport de sortie (.json ou .html).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Sortie détaillée.")
    parser.add_argument("--version", action="version",
                        version=f"IRON MAN AI {__version__}")

    wifi = parser.add_argument_group("Mode WiFi (réseau possédé)")
    wifi.add_argument("--wifi", action="store_true",
                      help="Lance le mode audit WiFi.")
    wifi.add_argument("-i", "--interface", default="wlan0",
                      help="Interface WiFi (mode monitor).")
    wifi.add_argument("-b", "--bssid", metavar="BSSID",
                      help="BSSID du réseau cible (AA:BB:CC:DD:EE:FF).")
    wifi.add_argument("--ssid", metavar="SSID",
                      help="SSID du réseau cible.")
    wifi.add_argument("--channel", type=int, default=0,
                      help="Canal du réseau cible (auto si 0).")
    wifi.add_argument("--crack", action="store_true",
                      help="Capture le handshake et cracke le mot de passe "
                           "(dictionnaire).")
    wifi.add_argument("--method", choices=["aircrack", "hashcat", "john"],
                      default="aircrack",
                      help="Outil de crack WPA2.")
    wifi.add_argument("-w", "--wordlist", metavar="FICHIER",
                      help="Dictionnaire de mots de passe (sinon wordlist "
                           "Kali par défaut).")
    wifi.add_argument("--wps", action="store_true",
                      help="Teste la vulnérabilité WPS (reaver).")
    wifi.add_argument("--scan-time", type=int, default=30,
                      help="Durée du scan des réseaux (secondes).")
    wifi.add_argument("--capture-time", type=int, default=120,
                      help="Durée de capture du handshake (secondes).")

    android = parser.add_argument_group("Mode Android (apps possédées)")
    android.add_argument("--android", action="store_true",
                         help="Lance le mode analyse Android.")
    android.add_argument("--apk", metavar="FICHIER",
                         help="Fichier APK/AAB à analyser.")
    android.add_argument("--no-secrets", action="store_true",
                         help="Désactive la détection de secrets.")
    android.add_argument("--no-code", action="store_true",
                         help="Désactive l'analyse du bytecode (dex).")
    android.add_argument("--jadx", action="store_true",
                         help="Enrichit l'analyse par décompilation complète "
                              "jadx (lent sur les grosses apps, ~10 min).")

    device = parser.add_argument_group("Mode Périphérique (adb — appareil "
                                       "possédé)")
    device.add_argument("--device", action="store_true",
                        help="Audit de posture d'un appareil Android "
                             "branché (adb, lecture seule).")
    device.add_argument("--serial", metavar="SERIAL",
                        help="Serial de l'appareil (auto si un seul "
                             "connecté).")
    return parser


def main(argv=None) -> int:
    """Point d'entrée CLI."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check:
        args.authorized = True  # la vérification est non destructive

    if not args.wifi and not args.android and not args.device:
        if not args.check:
            parser.error("Indiquez un mode : --wifi, --android ou --device "
                         "(ou --check pour vérifier les outils).")
        # --check seul : vérifie les outils des trois modes
        rc = _run_wifi(args)
        rc |= _run_android(args)
        rc |= _run_device(args)
        return 1 if rc else 0

    if not args.check and not args.authorized:
        print("[ERREUR] --authorized est obligatoire (confirmation que vous "
              "êtes autorisé à tester cette cible).", file=sys.stderr)
        return 2

    if args.wifi:
        return _run_wifi(args)
    if args.device:
        return _run_device(args)
    return _run_android(args)


if __name__ == "__main__":
    raise SystemExit(main())

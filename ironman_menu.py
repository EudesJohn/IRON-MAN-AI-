#!/usr/bin/env python3
"""
IRON MAN AI — Menu Interactif
L'utilisateur répond à des questions, jamais de commandes manuelles.
"""

import os
import sys
import subprocess
import json
from datetime import datetime

# Fix Windows encoding for Unicode characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    # Enable ANSI colors on Windows
    os.system('')

# ─── Couleurs ──────────────────────────────────────────────────
R = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"


def banner():
    print(f"""
{YELLOW}╔═══════════════════════════════════════════════════════════════╗
║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗                       ║
║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                        ║
║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                          ║
║                 IRON MAN AI — Menu Interactif               ║
║                 Pentest Autonome & Intégral                 ║
║                 Fait par Eudes Johnson                      ║
╚═══════════════════════════════════════════════════════════════╝{R}
""")


def ask(question, options=None, default=None):
    """Pose une question et retourne la réponse."""
    print(f"\n{CYAN}  ❓ {question}{R}")
    if options:
        for i, opt in enumerate(options, 1):
            marker = " (défaut)" if opt == default else ""
            print(f"    {YELLOW}[{i}]{R} {opt}{marker}")
    
    while True:
        try:
            answer = input(f"  {GREEN}→ Votre choix : {R}").strip()
            if not answer and default:
                return default
            if options and answer.isdigit():
                idx = int(answer) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            if not options:
                return answer
            print(f"    {RED}Choix invalide. Tapez le numéro ou le texte.{R}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}  Annulé.{R}")
            sys.exit(0)


def ask_url():
    """Demande l'URL cible."""
    url = ask(
        "Quelle est l'URL du site à auditer ?",
        default=""
    )
    if url and not url.startswith("http"):
        url = "https://" + url
    return url


def ask_authorized():
    """Demande l'autorisation."""
    resp = ask(
        "Avez-vous l'autorisation d'auditer cette cible ?",
        options=["Oui, j'ai l'autorisation", "Non, je veux tester"],
        default="Oui, j'ai l'autorisation"
    )
    return "oui" in resp.lower()


def ask_scan_type():
    """Demande le type de scan."""
    return ask(
        "Quel type de scan voulez-vous lancer ?",
        options=[
            "Scan complet (recommandé) — tous les outils",
            "Scan rapide — nmap + sslscan + whatweb",
            "Scan d'attaque — avec exploitation SQL/XSS/bruteforce",
            "Scan web avancé — gobuster + nikto + nuclei",
            "Scan WiFi — scan des réseaux à proximité",
            "Scan Android — analyse d'un fichier APK",
            "Audit périphérique — sécurité de votre téléphone",
        ],
        default="Scan complet (recommandé) — tous les outils"
    )


def ask_pdf():
    """Demande si on veut un PDF."""
    resp = ask(
        "Voulez-vous un rapport PDF ?",
        options=["Oui", "Non"],
        default="Oui"
    )
    return resp == "Oui"


def ask_exploit():
    """Demande si on veut l'exploitation."""
    resp = ask(
        "Voulez-vous l'exploitation automatique des failles ?",
        options=["Oui, tout exploiter", "Non, scan seulement"],
        default="Non, scan seulement"
    )
    return "oui" in resp.lower()


def ask_apk_path():
    """Demande le chemin de l'APK."""
    return ask("Quel est le chemin vers le fichier APK ?")


def ask_wifi_bssid():
    """Demande le BSSID WiFi."""
    return ask("Quel est le BSSID du réseau WiFi ? (format: AA:BB:CC:DD:EE:FF)")


def run_scan(url, scan_type, authorized, pdf, exploit):
    """Lance le scan avec les paramètres choisis."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{BLUE}{'═'*60}{R}")
    print(f"{BLUE}  LANCEMENT DU SCAN{R}")
    print(f"{BLUE}{'═'*60}{R}")
    print(f"  Cible    : {url}")
    print(f"  Type     : {scan_type}")
    print(f"  PDF      : {'Oui' if pdf else 'Non'}")
    print(f"  Exploit  : {'Oui' if exploit else 'Non'}")
    print(f"{BLUE}{'═'*60}{R}\n")
    
    # Construire la commande
    cmd = [sys.executable, os.path.join(base_dir, "kali_scan.py")]
    cmd.extend(["--url", url])
    
    if authorized:
        cmd.append("--authorized")
    
    if "attaque" in scan_type.lower() or "complet" in scan_type.lower():
        cmd.append("--attack")
    
    if exploit:
        cmd.append("--exploit")
    
    if pdf:
        cmd.append("--pdf")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = os.path.join(base_dir, "rapports", f"audit_{timestamp}")
    cmd.extend(["-o", output])
    
    print(f"{CYAN}  Commande : {' '.join(cmd)}{R}\n")
    
    try:
        proc = subprocess.run(cmd, cwd=base_dir, timeout=600)
        if proc.returncode == 0:
            print(f"\n{GREEN}  ✅ Scan terminé avec succès !{R}")
        else:
            print(f"\n{YELLOW}  ⚠️ Scan terminé (code: {proc.returncode}){R}")
    except subprocess.TimeoutExpired:
        print(f"\n{RED}  ❌ Timeout (10 minutes). Le scan est trop long.{R}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Interrompu par l'utilisateur.{R}")


def run_android(apk_path, authorized):
    """Lance l'analyse Android."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{BLUE}═══ ANALYSE ANDROID ═══{R}")
    print(f"  APK : {apk_path}\n")
    
    cmd = [
        sys.executable,
        os.path.join(base_dir, "mobile_scan.py"),
        "--android", "--apk", apk_path,
    ]
    if authorized:
        cmd.append("--authorized")
    
    try:
        subprocess.run(cmd, cwd=base_dir, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"{RED}  Timeout{R}")


def run_wifi(bssid, authorized):
    """Lance le scan WiFi."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{BLUE}═══ SCAN WiFi ═══{R}")
    print(f"  BSSID : {bssid}\n")
    
    cmd = [
        sys.executable,
        os.path.join(base_dir, "mobile_scan.py"),
        "--wifi", "--bssid", bssid,
    ]
    if authorized:
        cmd.append("--authorized")
    
    try:
        subprocess.run(cmd, cwd=base_dir, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"{RED}  Timeout{R}")


def run_device(authorized):
    """Lance l'audit du périphérique."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{BLUE}═══ AUDIT PÉRIPHÉRIQUE ═══{R}\n")
    
    cmd = [
        sys.executable,
        os.path.join(base_dir, "mobile_scan.py"),
        "--device",
    ]
    if authorized:
        cmd.append("--authorized")
    
    try:
        subprocess.run(cmd, cwd=base_dir, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"{RED}  Timeout{R}")


def run_github_analysis(repo_url):
    """Lance l'analyse de code depuis un lien GitHub."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{BLUE}{'═'*60}{R}")
    print(f"{BLUE}  ANALYSE DE CODE — GITHUB{R}")
    print(f"{BLUE}{'═'*60}{R}")
    print(f"  Depot   : {repo_url}")
    print(f"{BLUE}{'═'*60}{R}\n")
    
    cmd = [
        sys.executable,
        os.path.join(base_dir, "main.py"),
        "--repo", repo_url,
    ]
    
    try:
        subprocess.run(cmd, cwd=base_dir, timeout=600)
    except subprocess.TimeoutExpired:
        print(f"{RED}  Timeout — l'analyse a pris trop de temps{R}")


def main():
    banner()
    
    while True:
        print(f"\n{YELLOW}  ═══ MENU PRINCIPAL ═══{R}")
        
        action = ask(
            "Que voulez-vous faire ?",
            options=[
                "🌐 Auditer un site web",
                "🔍 Analyser du code (lien GitHub)",
                "📱 Analyser un fichier Android (APK)",
                "📡 Scanner un réseau WiFi",
                "📱 Auditer mon téléphone",
                "🔑 Tester le brute-force d'un login",
                "📊 Voir les rapports existants",
                "❌ Quitter",
            ],
            default="🌐 Auditer un site web"
        )
        
        # ── Audit web ──
        if "site web" in action.lower() or "web" in action.lower():
            url = ask_url()
            if not url:
                print(f"{RED}  URL requise.{R}")
                continue
            
            authorized = ask_authorized()
            scan_type = ask_scan_type()
            pdf = ask_pdf()
            exploit = ask_exploit()
            
            confirm = ask(
                f"Confirmer le scan de {url} ?",
                options=["Oui, lancer", "Non, annuler"],
                default="Oui, lancer"
            )
            
            if "oui" in confirm.lower():
                run_scan(url, scan_type, authorized, pdf, exploit)
        
        # ── Analyse GitHub ──
        elif "github" in action.lower() or "analyser du code" in action.lower():
            repo_url = ask(
                "Quel est le lien GitHub du depot ?",
                default=""
            )
            if not repo_url:
                print(f"{RED}  URL requise.{R}")
                continue
            run_github_analysis(repo_url)

        # ── Analyse Android ──
        elif "android" in action.lower() or "apk" in action.lower():
            apk = ask_apk_path()
            if not apk or not os.path.exists(apk):
                print(f"{RED}  Fichier introuvable : {apk}{R}")
                continue
            authorized = ask_authorized()
            run_android(apk, authorized)
        
        # ── Scan WiFi ──
        elif "wifi" in action.lower():
            bssid = ask_wifi_bssid()
            if not bssid:
                print(f"{RED}  BSSID requis.{R}")
                continue
            authorized = ask_authorized()
            run_wifi(bssid, authorized)
        
        # ── Audit périphérique ──
        elif "téléphone" in action.lower() or "périphérique" in action.lower():
            authorized = ask_authorized()
            run_device(authorized)
        
        # ── Brute-force ──
        elif "brute" in action.lower() or "login" in action.lower():
            url = ask_url()
            if not url:
                print(f"{RED}  URL requise.{R}")
                continue
            
            print(f"\n{CYAN}  Lancement du brute-force sur {url}...{R}")
            base_dir = os.path.dirname(os.path.abspath(__file__))
            cmd = [
                sys.executable,
                os.path.join(base_dir, "exploit_now.py"),
                url, "--authorized",
            ]
            try:
                subprocess.run(cmd, cwd=base_dir, timeout=600)
            except subprocess.TimeoutExpired:
                print(f"{RED}  Timeout{R}")
        
        # ── Voir rapports ──
        elif "rapport" in action.lower():
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rapports_dir = os.path.join(base_dir, "rapports")
            if os.path.isdir(rapports_dir):
                files = sorted(os.listdir(rapports_dir), reverse=True)
                if files:
                    print(f"\n{CYAN}  Rapports disponibles :{R}")
                    for f in files[:20]:
                        size = os.path.getsize(os.path.join(rapports_dir, f))
                        print(f"    📄 {f} ({size:,} octets)")
                else:
                    print(f"\n{YELLOW}  Aucun rapport disponible.{R}")
            else:
                print(f"\n{YELLOW}  Dossier rapports/ introuvable.{R}")
        
        # ── Quitter ──
        elif "quitter" in action.lower() or "quit" in action.lower():
            print(f"\n{GREEN}  Au revoir ! 🛡️{R}\n")
            break
        
        # ── Retour au menu ──
        ask("\nAppuyez sur Entrée pour revenir au menu...")


if __name__ == "__main__":
    main()

# 🛡️ IRON MAN AI — Pentest Autonome & Intégral

> **Audit de sécurité complet** : scan web, injection SQL, brute-force, analyse Android, contrôle de téléphone, scan WiFi — tout en un seul outil.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Kali-brightgreen.svg)]()

---

## ⚡ Installation Rapide

### Linux / Kali / WSL (une seule commande)

```bash
# Option 1 : Installation directe
git clone https://github.com/EudesJohn/IRON-MAN-AI-.git
cd IRON-MAN-AI-/codescan
sudo bash setup.sh

# Option 2 : Télécharger et installer
curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/setup.sh | sudo bash
```

### Windows

```batch
# 1. Installer Python (cocher "Add to PATH") :
#    https://www.python.org/downloads/

# 2. Installer Git :
#    https://git-scm.com/download/win

# 3. Ouvrir PowerShell et lancer :
git clone https://github.com/EudesJohn/IRON-MAN-AI-.git
cd IRON-MAN-AI-/codescan
.\install.bat
```

### Docker (alternatif)

```bash
docker run -it --rm -v $(pwd)/rapports:/app/rapports ironman-ai
```

---

## 🚀 Utilisation

### Menu Interactif (recommandé pour les débutants)

```bash
python ironman_menu.py
```

L'utilisateur répond simplement aux questions — **aucune commande à taper** :
```
❓ Que voulez-vous faire ?
    [1] 🌐 Auditer un site web
    [2] 📱 Analyser un fichier Android (APK)
    [3] 📡 Scanner un réseau WiFi
    [4] 📱 Auditer mon téléphone
    [5] 🔑 Tester le brute-force d'un login
    [6] 📊 Voir les rapports existants

→ Votre choix : 1

❓ Quelle est l'URL du site à auditer ?
→ Votre choix : https://example.com

❓ Avez-vous l'autorisation d'auditer cette cible ?
    [1] Oui, j'ai l'autorisation (défaut)
    [2] Non, je veux tester
→ Votre choix : 1

❓ Quel type de scan voulez-vous lancer ?
    [1] Scan complet (recommandé)
    [2] Scan rapide
    [3] Scan d'attaque
→ Votre choix : 1
```

### Ligne de Commande

```bash
# Scan web complet
python kali_scan.py --url https://cible.com --authorized --attack --exploit --pdf

# Exploitation directe (WAF bypass)
python exploit_now.py "https://cible.com/?id=1" --authorized

# Analyse Android
python mobile_scan.py --android --apk app.apk --authorized --jadx

# Audit WiFi
python mobile_scan.py --wifi --bssid AA:BB:CC:DD:EE:FF --authorized --crack

# Audit téléphone
python mobile_scan.py --device --authorized
```

---

## 🛠️ Ce que IRON MAN AI fait

| Module | Fonctionnalité |
|---|---|
| **🌐 Audit Web** | nmap, nikto, gobuster, sslscan, nuclei, wafw00f, dnsrecon |
| **💉 Injection SQL** | sqlmap avec WAF bypass (tamper, Tor, multi-stratégie) |
| **🔑 Brute-Force** | hydra sur admin panels, API login, SSH, FTP |
| **📡 Scan WiFi** | airodump-ng, crack WPA2, WPS (reaver/bully) |
| **📱 Analyse Android** | apktool, jadx, permissions, secrets, code à risque |
| **📱 Audit Téléphone** | ADB : verrou, chiffrement, SELinux, bootloader |
| **🎮 Contrôle Téléphone** | scrcpy : USB, WiFi, tunnel SSH à distance |
| **🧠 Explications** | Chaque finding expliqué "comme à un enfant de 5 ans" |
| **🎯 Exploitation Auto** | nikto, nuclei, CORS, headers, WAF bypass |
| **📊 Rapports** | JSON, HTML, PDF — horodatés, jamais écrasés |

---

## 📁 Structure du Projet

```
IRON-MAN-AI-/
├── codescan/
│   ├── kali_scan.py          # Audit web principal
│   ├── exploit_now.py         # Exploitation directe avec WAF bypass
│   ├── ironman_menu.py        # Menu interactif
│   ├── mobile_scan.py         # Android, WiFi, périphérique
│   ├── main.py                # CodeScan (analyse statique)
│   ├── kali/                  # Modules Kali (parsers, exploits, runner)
│   │   ├── auto_exploit.py    # Exploitation automatique
│   │   ├── waf_bypass.py      # Contournement WAF
│   │   ├── exploits.py        # Wordlists + explications
│   │   ├── parsers.py         # Sorties d'outils → findings
│   │   └── runner.py          # Exécution des outils
│   ├── scanner/               # Moteur d'analyse statique
│   ├── reports/               # Génération de rapports
│   ├── rapports/              # Rapports générés
│   ├── docs/                  # Manuels (PDF, HTML)
│   ├── tests/                 # 304+ tests automatisés
│   ├── setup.sh               # Installation rapide Linux
│   ├── install.sh             # Installation complète Linux
│   ├── install.bat            # Installation Windows
│   └── requirements.txt       # Dépendances Python
├── Intelligence Artificielle/ # Module IA (séparé)
└── README.md
```

---

## 📊 Outils Installés

| Catégorie | Outils |
|---|---|
| **Scan réseau** | nmap, dnsrecon, whois |
| **Scan web** | nikto, whatweb, gobuster, dirsearch, sslscan, nuclei, wafw00f |
| **Injection SQL** | sqlmap (avec WAF bypass : tamper, random-agent, Tor) |
| **Brute-force** | hydra (HTTP, SSH, FTP, MySQL — 107+ credentials) |
| **XSS** | xsstrike |
| **Command injection** | commix |
| **WiFi** | aircrack-ng, reaver, bully, pixiewps |
| **Android** | apktool, jadx, adb |
| **Contrôle téléphone** | scrcpy (USB, WiFi, SSH tunnel) |

---

## ⚠️ Avertissement

**IRON MAN AI** est un outil de **pentest autorisé uniquement**. 

- ✅ Vous devez avoir **l'autorisation écrite** du propriétaire de la cible
- ✅ Utilisez-le uniquement pour des **tests de sécurité légitimes**
- ❌ Toute utilisation non autorisée est **illégale** et punie par la loi

L'outil inclut des protections :
- Flag `--authorized` obligatoire pour les scans
- Mode SAFE : pas de reverse shell, pas de destruction
- Exploitation limitée à la **preuve** que la faille est exploitable

---

## 📚 Documentation

- [Manuel complet](MANUEL.md) — options, règles, personnalisation
- [Manuel Kali](docs/MANUEL_KALI.html) — guide d'installation Kali
- [Manuel Windows](docs/MANUEL_WINDOWS.html) — guide d'installation Windows
- [Manuel WiFi](docs/MANUEL_WIFI.html) — pentest WiFi
- [Manuel Android](docs/MANUEL_ANDROID.html) — analyse APK
- [Manuel Périphérique](docs/MANUEL_DEVICE.html) — audit téléphone
- [Manuel Contrôle](docs/MANUEL_CONTROLE.html) — scrcpy à distance

---

## 🧪 Tests

```bash
# Lancer les 304+ tests
cd codescan
python -m pytest tests/ -v
```

---

## 📄 Licence

MIT — Utilisez librement, maisresponsablement.

---

*Généré par IRON MAN AI 🤖*

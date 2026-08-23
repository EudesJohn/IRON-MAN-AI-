#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   IRON MAN AI — Installateur Universel (Linux / WSL / Kali)
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="${HOME}/iron-man-ai"
VENV_DIR="${INSTALL_DIR}/venv"

print_banner() {
    echo -e "${YELLOW}"
    cat << 'BANNER'
    ╔═══════════════════════════════════════════════════════╗
    ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
    ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
    ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
    ║         IRON MAN AI — Installation                  ║
    ║         Pentest Autonome & Intégral                 ║
    ║         Fait par Eudes Johnson                      ║
    ╚═══════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERREUR] Ce script doit être lancé en tant que root (sudo)${NC}"
        echo "Relancez avec : sudo bash install.sh"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        VER=""
    fi
    echo -e "${CYAN}[INFO] Système détecté : ${OS} ${VER}${NC}"
}

install_system_deps() {
    echo -e "${BLUE}[1/6] Installation des dépendances système...${NC}"
    
    apt-get update -qq
    
    # Python + pip
    apt-get install -y -qq python3 python3-pip python3-venv python3-dev \
        git curl wget unzip build-essential libssl-dev libffi-dev \
        2>/dev/null
    
    # Outils réseau
    apt-get install -y -qq nmap dnsutils whois net-tools \
        2>/dev/null
    
    echo -e "${GREEN}  ✅ Dépendances système installées${NC}"
}

install_kali_tools() {
    echo -e "${BLUE}[2/6] Installation des outils Kali / Pentest...${NC}"
    
    TOOLS=(
        "nmap"           # Scan réseau
        "nikto"          # Scan web
        "whatweb"        # Détection technologies
        "gobuster"       # Bruteforce répertoires
        "dirsearch"      # Bruteforce répertoires
        "sslscan"        # Scan SSL/TLS
        "nuclei"         # Scan vulnérabilités
        "wafw00f"        # Détection WAF
        "dnsrecon"       # Enum DNS
        "sqlmap"         # Injection SQL
        "hydra"          # Bruteforce login
        "aircrack-ng"    # Crack WiFi
        "reaver"         # Crack WPS
        "bully"          # Crack WPS
        "pixiewps"       # Crack WPS
        "curl"           # HTTP client
        "wget"           # Téléchargement
        "whois"          # Info domaine
    )
    
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✅ $tool${NC} (déjà installé)"
        else
            echo -e "  ${YELLOW}⏳ Installation de $tool...${NC}"
            apt-get install -y -qq "$tool" 2>/dev/null || \
            pip3 install "$tool" 2>/dev/null || \
            echo -e "  ${RED}  ⚠️ $tool non disponible — installation manuelle requise${NC}"
        fi
    done
    
    # Outils spéciaux
    if ! command -v commix &>/dev/null; then
        echo -e "  ${YELLOW}⏳ Installation de commix...${NC}"
        pip3 install commix 2>/dev/null || echo -e "  ${RED}  ⚠️ commix${NC}"
    fi
    
    if ! command -v xsstrike &>/dev/null; then
        echo -e "  ${YELLOW}⏳ Installation de xsstrike...${NC}"
        pip3 install xsstrike 2>/dev/null || echo -e "  ${RED}  ⚠️ xsstrike${NC}"
    fi
    
    # Apktool + jadx (analyse Android)
    if ! command -v apktool &>/dev/null; then
        echo -e "  ${YELLOW}⏳ Installation de apktool...${NC}"
        wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" -O /usr/local/bin/apktool 2>/dev/null
        wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" -O /usr/local/bin/apktool.jar 2>/dev/null
        chmod +x /usr/local/bin/apktool 2>/dev/null
    fi
    
    if ! command -v jadx &>/dev/null; then
        echo -e "  ${YELLOW}⏳ Installation de jadx...${NC}"
        JADX_VER="1.5.0"
        wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -O /tmp/jadx.zip 2>/dev/null
        unzip -qo /tmp/jadx.zip -d /opt/jadx 2>/dev/null
        ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx 2>/dev/null
        rm -f /tmp/jadx.zip
    fi
    
    echo -e "${GREEN}  ✅ Outils Kali installés${NC}"
}

install_scrcpy() {
    echo -e "${BLUE}[3/6] Installation de scrcpy (contrôle téléphone)...${NC}"
    
    if command -v scrcpy &>/dev/null; then
        echo -e "  ${GREEN}✅ scrcpy${NC} (déjà installé)"
    else
        apt-get install -y -qq scrcpy 2>/dev/null || {
            echo -e "  ${YELLOW}⏳ Installation manuelle de scrcpy...${NC}"
            apt-get install -y -qq adb ffmpeg libsdl2-2.0-0 2>/dev/null
            SCRCPY_VER="2.6.1"
            wget -q "https://github.com/Genymobile/scrcpy/releases/download/v${SCRCPY_VER}/scrcpy-linux-x86_64-v${SCRCPY_VER}.tar.gz" -O /tmp/scrcpy.tar.gz 2>/dev/null
            tar xzf /tmp/scrcpy.tar.gz -C /opt/ 2>/dev/null
            ln -sf /opt/scrcpy-linux-x86_64-v${SCRCPY_VER}/scrcpy /usr/local/bin/scrcpy 2>/dev/null
            rm -f /tmp/scrcpy.tar.gz
        }
    fi
    
    echo -e "${GREEN}  ✅ scrcpy installé${NC}"
}

install_python_deps() {
    echo -e "${BLUE}[4/6] Installation des dépendances Python...${NC}"
    
    cd "${INSTALL_DIR}"
    
    # Créer le virtualenv
    python3 -m venv "${VENV_DIR}" 2>/dev/null || python3 -m virtualenv "${VENV_DIR}" 2>/dev/null
    source "${VENV_DIR}/bin/activate"
    
    # Installer les dépendances
    pip install --upgrade pip -q 2>/dev/null
    pip install -r requirements.txt -q 2>/dev/null
    
    # Dépendances supplémentaires
    pip install requests beautifulsoup4 pystache fpdf2 -q 2>/dev/null
    
    echo -e "${GREEN}  ✅ Dépendances Python installées${NC}"
}

setup_ironman() {
    echo -e "${BLUE}[5/6] Configuration de IRON MAN AI...${NC}"
    
    # Créer les répertoires
    mkdir -p "${INSTALL_DIR}/rapports"
    mkdir -p "${INSTALL_DIR}/docs"
    
    # Rendre les scripts exécutables
    chmod +x "${INSTALL_DIR}/kali_scan.py" 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/exploit_now.py" 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/main.py" 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/ironman.py" 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/mobile_scan.py" 2>/dev/null || true
    
    # Créer le lien symbolique global
    ln -sf "${INSTALL_DIR}/kali_scan.py" /usr/local/bin/ironman 2>/dev/null || true
    
    echo -e "${GREEN}  ✅ IRON MAN AI configuré${NC}"
}

verify_installation() {
    echo -e "${BLUE}[6/6] Vérification de l'installation...${NC}"
    
    OK=0
    FAIL=0
    
    for cmd in python3 nmap nikto whatweb gobuster sslscan nuclei wafw00f sqlmap hydra; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}✅ $cmd${NC}"
            OK=$((OK+1))
        else
            echo -e "  ${RED}❌ $cmd${NC}"
            FAIL=$((FAIL+1))
        fi
    done
    
    echo ""
    echo -e "${CYAN}  Résultat : ${OK} installés, ${FAIL} manquants${NC}"
}

print_usage() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ IRON MAN AI installé avec succès !${NC}"
    echo ""
    echo -e "  ${CYAN}Pour lancer :${NC}"
    echo -e "    cd ${INSTALL_DIR}"
    echo -e "    source venv/bin/activate"
    echo ""
    echo -e "  ${CYAN}Scan web complet :${NC}"
    echo -e "    python kali_scan.py --url https://cible.com --authorized --attack --pdf"
    echo ""
    echo -e "  ${CYAN}Exploitation directe :${NC}"
    echo -e "    python exploit_now.py https://cible.com/?id=1 --authorized"
    echo ""
    echo -e "  ${CYAN}Menu interactif :${NC}"
    echo -e "    python ironman.py --menu"
    echo ""
    echo -e "  ${CYAN}Analyse Android :${NC}"
    echo -e "    python mobile_scan.py --android --apk app.apk --authorized"
    echo ""
    echo -e "  ${CYAN}Scan WiFi :${NC}"
    echo -e "    python mobile_scan.py --wifi --bssid AA:BB:CC:DD:EE:FF --authorized"
    echo ""
    echo -e "  ${CYAN}Audit périphérique :${NC}"
    echo -e "    python mobile_scan.py --device --authorized"
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
}

# === MAIN ===
print_banner
check_root
detect_os
install_system_deps
install_kali_tools
install_scrcpy
install_python_deps
setup_ironman
verify_installation
print_usage

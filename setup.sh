#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   IRON MAN AI — Installation Rapide (une seule commande)
#
#   Usage :
#     curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/setup.sh | sudo bash
#
#   Ou :
#     git clone https://github.com/EudesJohn/IRON-MAN-AI-.git
#     cd IRON-MAN-AI-/codescan
#     sudo bash setup.sh
# ═══════════════════════════════════════════════════════════════

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; NC='\033[0m'

echo -e "${Y}"
cat << 'EOF'
    ╔═══════════════════════════════════════════════════════╗
    ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
    ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
    ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
    ║         IRON MAN AI — Installation Rapide           ║
    ╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Vérifier root
if [ "$EUID" -ne 0 ]; then
    echo -e "${R}[ERREUR] Relancez avec : sudo bash setup.sh${NC}"
    exit 1
fi

# Détecter le répertoire du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/iron-man-ai"

echo -e "${C}[1/5] Détection du système...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "  ${G}✅ ${ID} ${VERSION_ID}${NC}"
else
    echo -e "  ${Y}⚠️ OS non identifié — tentative d'installation...${NC}"
fi

echo -e "${C}[2/5] Installation des outils...${NC}"
apt-get update -qq 2>/dev/null
apt-get install -y -qq python3 python3-pip python3-venv git curl wget unzip \
    nmap nikto whatweb gobuster dirsearch sslscan nuclei wafw00f dnsrecon \
    sqlmap hydra aircrack-ng reaver bully pixiewps scrcpy adb 2>/dev/null || true

# Outils Python
pip3 install sqlmap 2>/dev/null || true
pip3 install commix 2>/dev/null || true
pip3 install xsstrike 2>/dev/null || true

echo -e "${C}[3/5] Copie de IRON MAN AI...${NC}"
mkdir -p "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/." "${INSTALL_DIR}/" 2>/dev/null || true

echo -e "${C}[4/5] Configuration Python...${NC}"
cd "${INSTALL_DIR}"
python3 -m venv venv 2>/dev/null || python3 -m virtualenv venv 2>/dev/null || true
source venv/bin/activate 2>/dev/null || true
pip install --upgrade pip -q 2>/dev/null || true
pip install -r requirements.txt -q 2>/dev/null || true
pip install requests beautifulsoup4 pystache fpdf2 -q 2>/dev/null || true

echo -e "${C}[5/5] Finalisation...${NC}"
mkdir -p "${INSTALL_DIR}/rapports"
chmod +x "${INSTALL_DIR}/kali_scan.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/exploit_now.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/ironman_menu.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/mobile_scan.py" 2>/dev/null || true
ln -sf "${INSTALL_DIR}/ironman_menu.py" /usr/local/bin/ironman 2>/dev/null || true

echo ""
echo -e "${G}══════════════════════════════════════════════════════════════${NC}"
echo -e "${G}  ✅ IRON MAN AI installé !${NC}"
echo ""
echo -e "  ${C}Lancer le menu interactif :${NC}"
echo -e "    cd ${INSTALL_DIR}"
echo -e "    python ironman_menu.py"
echo ""
echo -e "  ${C}Ou en ligne de commande :${NC}"
echo -e "    python kali_scan.py --url https://cible.com --authorized --attack --pdf"
echo -e "${G}══════════════════════════════════════════════════════════════${NC}"

#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   IRON MAN AI — Désinstallation
#
#   Commande :
#     ironman --uninstall
#
#   Ou directement :
#     curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/uninstall.sh | bash
# ═══════════════════════════════════════════════════════════════

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

INSTALL_DIR="${HOME}/iron-man-ai"
BIN_DIR="/usr/local/bin"

echo -e "${R}"
cat << 'EOF'
    ╔═══════════════════════════════════════════════════════╗
    ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
    ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
    ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
    ║              DÉSINSTALLATION                        ║
    ╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${Y}  ⚠️  Cette opération va supprimer IRON MAN AI de votre PC${NC}"
echo ""
echo -e "  Ce qui sera supprimé :"
echo -e "    📂 ${INSTALL_DIR}"
echo -e "    🔗 ${BIN_DIR}/ironman"
echo -e "    🔗 ${BIN_DIR}/IRON-MAN-AI"
echo ""

read -p "  Confirmer la désinstallation ? (y/N) : " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${C}  Annulé. IRON MAN AI reste installé.${NC}"
    exit 0
fi

echo ""
echo -e "${R}  🗑️  Suppression en cours...${NC}"

# Supprimer le répertoire d'installation
if [ -d "${INSTALL_DIR}" ]; then
    rm -rf "${INSTALL_DIR}"
    echo -e "    ${G}✅ ${INSTALL_DIR} supprimé${NC}"
fi

# Supprimer les commandes globales
for cmd in ironman IRON-MAN-AI; do
    if [ -f "${BIN_DIR}/${cmd}" ]; then
        rm -f "${BIN_DIR}/${cmd}"
        echo -e "    ${G}✅ ${cmd} supprimé${NC}"
    fi
done

echo ""
echo -e "${G}══════════════════════════════════════════════════════════════${NC}"
echo -e "${G}  ✅ IRON MAN AI a été désinstallé !${NC}"
echo ""
echo -e "  ${C}Pour réinstaller à tout moment :${NC}"
echo -e "    curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/install_anywhere.sh | sudo bash"
echo -e "${G}══════════════════════════════════════════════════════════════${NC}"

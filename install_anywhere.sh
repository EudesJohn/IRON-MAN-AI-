#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   IRON MAN AI — Installation Universelle
#
#   UNE SEULE COMMANDE pour installer tout :
#
#     curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/install_anywhere.sh | sudo bash
#
#   Après installation, tapez simplement :
#     ironman
#
#   Mise à jour :
#     ironman --update
#
#   Désinstallation :
#     ironman --uninstall
# ═══════════════════════════════════════════════════════════════

set -e

# ─── Couleurs ───────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'

INSTALL_DIR="${HOME}/iron-man-ai"
BIN_DIR="/usr/local/bin"

# ─── Banner ─────────────────────────────────────────────────
clear
echo -e "${M}"
cat << 'EOF'

    ██╗███╗   ██╗██╗   ██╗ █████╗ ██████╗ ████████╗
    ██║████╗  ██║██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
    ██║██╔██╗ ██║██║   ██║███████║██████╔╝   ██║   
    ██║██║╚██╗██║╚██╗ ██╔╝██╔══██║██╔══██╗   ██║   
    ██║██║ ╚████║ ╚████╔╝ ██║  ██║██║  ██║   ██║   
    ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
                ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗
                ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝ 
                ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩  
                    INSTALLATION UNIVERSELLE

EOF
echo -e "${NC}"

# ─── Détection OS ───────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Linux*)   PLATFORM="linux";;
    Darwin*)  PLATFORM="macos";;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows";;
    *)        PLATFORM="unknown";;
esac

echo -e "${C}  [INFO] Système détecté : ${OS} ${ARCH} (${PLATFORM})${NC}"
echo ""

# ─── Vérifier root ─────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${Y}  ⚠️  Installation en mode utilisateur (certains outils nécessitent sudo)${NC}"
    echo -e "${Y}     Pour une installation complète : sudo bash $0${NC}"
    echo ""
    IS_ROOT=0
else
    IS_ROOT=1
fi

# ─── [1/6] Vérifier Python ─────────────────────────────────
echo -e "${BOLD}${B}  [1/6] Vérification de Python...${NC}"

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "    ${R}❌ Python non trouvé !${NC}"
    echo ""
    echo -e "    Installez Python :"
    echo -e "      ${C}https://www.python.org/downloads/${NC}"
    echo -e "      Cochez \"Add Python to PATH\""
    echo ""
    exit 1
fi

PY_VER=$($PYTHON --version 2>&1)
echo -e "    ${G}✅ ${PY_VER}${NC}"

# Vérifier version minimale
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
    echo -e "    ${R}❌ Python 3.8+ requis (trouvé : ${PY_VER})${NC}"
    exit 1
fi

# ─── [2/6] Installer pip si manquant ────────────────────────
echo -e "${BOLD}${B}  [2/6] Vérification de pip...${NC}"

if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "    ${Y}⏳ Installation de pip...${NC}"
    $PYTHON -m ensurepip --upgrade 2>/dev/null || {
        curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON 2>/dev/null
    }
fi
echo -e "    ${G}✅ pip OK${NC}"

# ─── [3/6] Cloner / mettre à jour le projet ────────────────
echo -e "${BOLD}${B}  [3/6] Préparation du projet...${NC}"

if [ -d "${INSTALL_DIR}" ]; then
    echo -e "    ${Y}📂 Projet existant détecté — mise à jour...${NC}"
    cd "${INSTALL_DIR}"
    if command -v git &>/dev/null && [ -d .git ]; then
        git pull origin main 2>/dev/null && echo -e "    ${G}✅ Mis à jour${NC}" || echo -e "    ${Y}⚠️ Pas de mise à jour disponible${NC}"
    fi
else
    echo -e "    ${Y}⏳ Clonage du dépôt...${NC}"
    if command -v git &>/dev/null; then
        git clone https://github.com/EudesJohn/IRON-MAN-AI-.git "${INSTALL_DIR}" 2>/dev/null
    else
        echo -e "    ${R}❌ Git non installé !${NC}"
        echo -e "    Installez Git : ${C}https://git-scm.com/download${NC}"
        exit 1
    fi
fi

# Copier depuis le script source si nécessaire
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -d "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/requirements.txt" ] && [ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]; then
    cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/" 2>/dev/null || true
fi

cd "${INSTALL_DIR}"
echo -e "    ${G}✅ Projet prêt dans ${INSTALL_DIR}${NC}"

# ─── [4/6] Virtualenv + dépendances Python ──────────────────
echo -e "${BOLD}${B}  [4/6] Installation des dépendances Python...${NC}"

VENV_DIR="${INSTALL_DIR}/venv"

if [ ! -d "${VENV_DIR}" ]; then
    echo -e "    ${Y}⏳ Création du virtualenv...${NC}"
    $PYTHON -m venv "${VENV_DIR}" 2>/dev/null || {
        $PYTHON -m pip install virtualenv -q 2>/dev/null
        $PYTHON -m virtualenv "${VENV_DIR}" 2>/dev/null
    }
fi

# Activer le venv
if [ -f "${VENV_DIR}/bin/activate" ]; then
    source "${VENV_DIR}/bin/activate"
elif [ -f "${VENV_DIR}/Scripts/activate" ]; then
    source "${VENV_DIR}/Scripts/activate"
fi

pip install --upgrade pip -q 2>/dev/null || true
pip install -r requirements.txt -q 2>/dev/null || true
pip install requests beautifulsoup4 pystache fpdf2 2>/dev/null || true

echo -e "    ${G}✅ Dépendances Python installées${NC}"

# ─── [5/6] Outils système ──────────────────────────────────
echo -e "${BOLD}${B}  [5/6] Installation des outils système...${NC}"

install_tool() {
    local tool=$1
    if command -v "$tool" &>/dev/null; then
        echo -e "      ${G}✅ $tool${NC}"
    else
        if [ "$IS_ROOT" -eq 1 ]; then
            echo -e "      ${Y}⏳ $tool...${NC}"
            apt-get install -y -qq "$tool" 2>/dev/null || \
            brew install "$tool" 2>/dev/null || \
            pip install "$tool" 2>/dev/null || \
            echo -e "      ${R}⚠️ $tool non disponible${NC}"
        else
            echo -e "      ${R}⚠️ $tool (nécessite sudo)${NC}"
        fi
    fi
}

if [ "$IS_ROOT" -eq 1 ]; then
    apt-get update -qq 2>/dev/null || true
fi

# Outils essentiels
for tool in nmap nikto whatweb gobuster sslscan nuclei wafw00f dnsrecon sqlmap hydra adb curl wget git; do
    install_tool "$tool"
done

# Outils additionnels
for tool in dirsearch sslscan aircrack-ng scrcpy; do
    install_tool "$tool"
done

echo -e "    ${G}✅ Outils système vérifiés${NC}"

# ─── [6/6] Créer la commande globale 'ironman' ─────────────
echo -e "${BOLD}${B}  [6/6] Configuration de la commande 'ironman'...${NC}"

# Créer le wrapper script
cat > "${BIN_DIR}/ironman" << 'WRAPPER'
#!/bin/bash
# ═══════════════════════════════════════════════════════════
#   IRON MAN AI — Point d'entrée global
# ═══════════════════════════════════════════════════════════

INSTALL_DIR="${HOME}/iron-man-ai"
VENV_DIR="${INSTALL_DIR}/venv"

# Couleurs
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'

# ─── Bannière ──────────────────────────────────────────────
show_banner() {
    echo -e "${C}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════╗
    ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
    ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
    ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
    ║           Pentest Autonome & Intégral               ║
    ╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ─── Commandes spéciales ───────────────────────────────────
case "$1" in
    --update|-u)
        echo -e "${Y}🔄 Mise à jour d'IRON MAN AI...${NC}"
        cd "${INSTALL_DIR}" 2>/dev/null || { echo -e "${R}❌ Installation non trouvée${NC}"; exit 1; }
        if [ -d .git ]; then
            git pull origin main
            echo -e "${G}✅ Mis à jour avec succès !${NC}"
        else
            echo -e "${R}❌ Dépôt git non trouvé — réinstallez avec :${NC}"
            echo -e "   curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/install_anywhere.sh | sudo bash"
        fi
        exit 0
        ;;
    --uninstall|--remove|-r)
        echo -e "${R}🗑️  Désinstallation d'IRON MAN AI...${NC}"
        echo ""
        read -p "    Supprimer ${INSTALL_DIR} ? (y/N) : " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "${INSTALL_DIR}"
            rm -f "${BIN_DIR}/ironman"
            echo -e "${G}✅ IRON MAN AI supprimé !${NC}"
        else
            echo -e "${C}Annulé.${NC}"
        fi
        exit 0
        ;;
    --help|-h)
        show_banner
        echo -e "  ${C}Utilisation :${NC}"
        echo ""
        echo -e "    ${G}ironman${NC}                  Lancer le menu interactif"
        echo -e "    ${G}ironman --scan <url>${NC}    Scan web rapide"
        echo -e "    ${G}ironman --exploit <url>${NC} Exploitation directe"
        echo -e "    ${G}ironman --update${NC}        Mettre à jour"
        echo -e "    ${G}ironman --uninstall${NC}     Désinstaller"
        echo -e "    ${G}ironman --help${NC}          Afficher cette aide"
        echo ""
        echo -e "  ${C}Exemples :${NC}"
        echo ""
        echo -e "    ironman"
        echo -e "    ironman --scan https://example.com"
        echo -e "    ironman --exploit 'https://example.com/?id=1'"
        echo -e "    ironman --update"
        echo -e "    ironman --uninstall"
        echo ""
        exit 0
        ;;
esac

# ─── Vérifier l'installation ───────────────────────────────
if [ ! -d "${INSTALL_DIR}" ]; then
    echo -e "${R}❌ IRON MAN AI non installé !${NC}"
    echo ""
    echo -e "  Installez avec :"
    echo -e "    ${C}curl -sL https://raw.githubusercontent.com/EudesJohn/IRON-MAN-AI-/main/install_anywhere.sh | sudo bash${NC}"
    exit 1
fi

# ─── Scanner rapide ────────────────────────────────────────
if [ "$1" = "--scan" ] && [ -n "$2" ]; then
    show_banner
    echo -e "${C}🔍 Scan web de : $2${NC}"
    echo ""
    cd "${INSTALL_DIR}"
    source "${VENV_DIR}/bin/activate" 2>/dev/null
    python kali_scan.py --url "$2" --authorized --attack --pdf
    exit $?
fi

# ─── Exploitation directe ──────────────────────────────────
if [ "$1" = "--exploit" ] && [ -n "$2" ]; then
    show_banner
    echo -e "${C}🎯 Exploitation de : $2${NC}"
    echo ""
    cd "${INSTALL_DIR}"
    source "${VENV_DIR}/bin/activate" 2>/dev/null
    python exploit_now.py "$2" --authorized
    exit $?
fi

# ─── Menu interactif (défaut) ──────────────────────────────
show_banner

cd "${INSTALL_DIR}"
source "${VENV_DIR}/bin/activate" 2>/dev/null

echo -e "  ${C}Tapez 'help' pour voir les commandes disponibles${NC}"
echo ""

# Lancer le menu interactif
if [ -f "${INSTALL_DIR}/ironman_menu.py" ]; then
    python "${INSTALL_DIR}/ironman_menu.py" "$@"
elif [ -f "${INSTALL_DIR}/kali_scan.py" ]; then
    echo -e "  ${Y}Menu interactif non disponible — mode ligne de commande${NC}"
    echo ""
    python "${INSTALL_DIR}/kali_scan.py" --help
else
    echo -e "${R}❌ Fichiers non trouvés dans ${INSTALL_DIR}${NC}"
    exit 1
fi
WRAPPER

chmod +x "${BIN_DIR}/ironman"

# Créer aussi le lien 'IRON-MAN-AI' (avec tirets) pour ceux qui tapent le nom complet
ln -sf "${BIN_DIR}/ironman" "${BIN_DIR}/IRON-MAN-AI" 2>/dev/null || true

echo -e "    ${G}✅ Commande 'ironman' créée${NC}"

# ─── Finalisation ───────────────────────────────────────────
mkdir -p "${INSTALL_DIR}/rapports"
chmod +x "${INSTALL_DIR}/kali_scan.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/exploit_now.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/ironman_menu.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/mobile_scan.py" 2>/dev/null || true

# ─── Résumé final ──────────────────────────────────────────
echo ""
echo -e "${M}══════════════════════════════════════════════════════════════${NC}"
echo -e "${G}  ✅ IRON MAN AI installé avec succès !${NC}"
echo ""
echo -e "  ${C}Pour commencer, tapez simplement :${NC}"
echo ""
echo -e "    ${BOLD}${G}ironman${NC}"
echo ""
echo -e "  ${C}Autres commandes :${NC}"
echo ""
echo -e "    ${G}ironman --scan <url>${NC}      Scan web rapide"
echo -e "    ${G}ironman --exploit <url>${NC}   Exploitation directe"
echo -e "    ${G}ironman --update${NC}          Mettre à jour"
echo -e "    ${G}ironman --uninstall${NC}       Désinstaller"
echo -e "    ${G}ironman --help${NC}            Aide"
echo ""
echo -e "${M}══════════════════════════════════════════════════════════════${NC}"

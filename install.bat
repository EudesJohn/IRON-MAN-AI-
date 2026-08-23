@echo off
chcp 65001 >nul
title IRON MAN AI — Installation Windows

echo.
echo  ╔═══════════════════════════════════════════════════════╗
echo  ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
echo  ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
echo  ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
echo  ║         IRON MAN AI — Installation Windows          ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.

set INSTALL_DIR=%USERPROFILE%\iron-man-ai
set PYTHON_DIR=%INSTALL_DIR%\venv

echo [1/5] Vérification de Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python n'est pas installé !
    echo.
    echo Téléchargez Python depuis : https://www.python.org/downloads/
    echo Cochez "Add Python to PATH" lors de l'installation !
    echo.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)
echo ✅ Python détecté
python --version

echo.
echo [2/5] Vérification de Git...
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Git n'est pas installé !
    echo Téléchargez Git depuis : https://git-scm.com/download/win
    start https://git-scm.com/download/win
    pause
    exit /b 1
)
echo ✅ Git détecté

echo.
echo [3/5] Clonage du dépôt...
if exist "%INSTALL_DIR%" (
    echo Répertoire existant, mise à jour...
    cd "%INSTALL_DIR%"
    git pull
) else (
    git clone https://github.com/EudesJohn/IRON-MAN-AI-.git "%INSTALL_DIR%"
    cd "%INSTALL_DIR%"
)

echo.
echo [4/5] Installation des dépendances Python...
python -m venv "%PYTHON_DIR%" 2>nul
call "%PYTHON_DIR%\Scripts\activate.bat"

pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt >nul 2>&1
pip install requests beautifulsoup4 pystache fpdf2 >nul 2>&1
pip install sqlmap hydra nmap nuclei >nul 2>&1

echo ✅ Dépendances Python installées

echo.
echo [5/5] Configuration...
if not exist "%INSTALL_DIR%\rapports" mkdir "%INSTALL_DIR%\rapports"

echo.
echo ══════════════════════════════════════════════════════════════
echo   ✅ IRON MAN AI installé avec succès !
echo.
echo   Pour lancer :
echo     cd %INSTALL_DIR%
echo     venv\Scripts\activate.bat
echo.
echo   Scan web :
echo     python kali_scan.py --url https://cible.com --authorized --attack --pdf
echo.
echo   Menu interactif :
echo     python ironman.py --menu
echo.
echo   Exploitation directe :
echo     python exploit_now.py https://cible.com/?id=1 --authorized
echo ══════════════════════════════════════════════════════════════
echo.
pause

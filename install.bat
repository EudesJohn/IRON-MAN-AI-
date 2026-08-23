@echo off
chcp 65001 >nul
title IRON MAN AI — Installation Windows

echo.
echo     ╔═══════════════════════════════════════════════════════╗
echo     ║   ╔═╗ ╦ ╦ ╔═╗ ╦   ╔╦╗╔═╗╔╗╔╦╔═╗╦═╗               ║
echo     ║   ╠═╝ ╚╦╝ ╠╣ ║    ║║║║║║║║║║║║╔═╝                ║
echo     ║   ╩    ╩  ╚═╝╩═╝═╩╝╚╩═╝╚╝╚╩╚═╝╩                  ║
echo     ║         IRON MAN AI — Installation Windows          ║
echo     ╚═══════════════════════════════════════════════════════╝
echo.

set INSTALL_DIR=%USERPROFILE%\iron-man-ai
set BIN_DIR=%USERPROFILE%\bin
set PYTHON_DIR=%INSTALL_DIR%\venv

:: ─── [1/6] Vérification de Python ─────────────────────────
echo   [1/6] Vérification de Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERREUR] Python n'est pas installé !
    echo.
    echo   Téléchargez Python depuis :
    echo     https://www.python.org/downloads/
    echo   Cochez "Add Python to PATH" lors de l'installation !
    echo.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version
echo   ✅ Python détecté

:: ─── [2/6] Vérification de Git ────────────────────────────
echo.
echo   [2/6] Vérification de Git...
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERREUR] Git n'est pas installé !
    echo   Téléchargez Git depuis : https://git-scm.com/download/win
    start https://git-scm.com/download/win
    pause
    exit /b 1
)
echo   ✅ Git détecté

:: ─── [3/6] Clonage du dépôt ───────────────────────────────
echo.
echo   [3/6] Préparation du projet...
if exist "%INSTALL_DIR%" (
    echo   📂 Projet existant détecté — mise à jour...
    cd /d "%INSTALL_DIR%"
    git pull origin main >nul 2>&1
    echo   ✅ Mis à jour
) else (
    echo   ⏳ Clonage du dépôt...
    git clone https://github.com/EudesJohn/IRON-MAN-AI-.git "%INSTALL_DIR%"
    cd /d "%INSTALL_DIR%"
)

:: Vérifier que codescan existe
if not exist "%INSTALL_DIR%\codescan" (
    echo   [ERREUR] Le dossier codescan n'existe pas dans %INSTALL_DIR%
    echo   Vérifiez que le clonage a réussi.
    pause
    exit /b 1
)

cd /d "%INSTALL_DIR%\codescan"
echo   ✅ Projet prêt dans %INSTALL_DIR%\codescan

:: ─── [4/6] Virtualenv + dépendances Python ─────────────────
echo.
echo   [4/6] Installation des dépendances Python...
if not exist "%PYTHON_DIR%" (
    python -m venv "%PYTHON_DIR%" 2>nul
)
call "%PYTHON_DIR%\Scripts\activate.bat"

pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt >nul 2>&1
pip install requests beautifulsoup4 pystache fpdf2 >nul 2>&1
echo   ✅ Dépendances Python installées

:: ─── [5/6] Outils système ─────────────────────────────────
echo.
echo   [5/6] Vérification des outils...
echo   ℹ️  Certains outils (nmap, sqlmap) nécessitent une installation manuelle sur Windows
echo   📥 Téléchargez nmap : https://nmap.org/download.html
echo   ✅ Outils Python installés

:: ─── [6/6] Créer la commande globale ──────────────────────
echo.
echo   [6/6] Configuration de la commande 'ironman'...

:: Créer le répertoire bin
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

:: Créer le script ironman.bat
> "%BIN_DIR%\ironman.bat" (
    echo @echo off
    echo cd /d "%INSTALL_DIR%"
    echo call "%PYTHON_DIR%\Scripts\activate.bat"
    echo.
    echo set CMD=%%1
    echo.
    echo if "%%CMD%"=="--update" ^(
    echo     echo 🔄 Mise à jour...
    echo     cd /d "%INSTALL_DIR%"
    echo     git pull origin main
    echo     echo ✅ Mis à jour !
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%CMD%"=="--uninstall" ^(
    echo     echo 🗑️  Suppression d'IRON MAN AI...
    echo     rmdir /s /q "%INSTALL_DIR%"
    echo     del "%BIN_DIR%\ironman.bat"
    echo     echo ✅ Désinstallé !
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%CMD%"=="--scan" ^(
    echo     python "%INSTALL_DIR%\codescan\kali_scan.py" --url %%2 --authorized --attack --pdf
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%CMD%"=="--exploit" ^(
    echo     python "%INSTALL_DIR%\codescan\exploit_now.py" "%%2" --authorized
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%CMD%"=="--help" ^(
    echo     echo.
    echo     echo   IRON MAN AI — Aide
    echo     echo   ═══════════════════════════════════════
    echo     echo.
    echo     echo   ironman                    Lancer le menu interactif
    echo     echo   ironman --scan ^<url^>       Scan web rapide
    echo     echo   ironman --exploit ^<url^>    Exploitation directe
    echo     echo   ironman --update           Mettre à jour
    echo     echo   ironman --uninstall        Désinstaller
    echo     echo   ironman --help             Aide
    echo     echo.
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%CMD%"=="" ^(
    echo     python "%INSTALL_DIR%\codescan\ironman_menu.py"
    echo ^) else ^(
    echo     echo [ERREUR] Commande inconnue : %%CMD%
    echo     echo Tapez : ironman --help
    echo ^)
)

:: Ajouter le répertoire bin au PATH (pour la session actuelle)
set PATH=%PATH%;%BIN_DIR%

:: Ajouter au PATH permanent
setx PATH "%PATH%" >nul 2>&1

echo   ✅ Commande 'ironman' créée dans %BIN_DIR%

:: ─── Finalisation ─────────────────────────────────────────
if not exist "%INSTALL_DIR%\rapports" mkdir "%INSTALL_DIR%\rapports"

echo.
echo ══════════════════════════════════════════════════════════════
echo   ✅ IRON MAN AI installé avec succès !
echo.
echo   Pour commencer, rouvrez un NOUVEAU terminal et tapez :
echo.
echo     ironman
echo.
echo   Autres commandes :
echo.
echo     ironman --scan ^<url^>        Scan web rapide
echo     ironman --exploit ^<url^>     Exploitation directe
echo     ironman --update            Mettre à jour
echo     ironman --uninstall         Désinstaller
echo     ironman --help              Aide
echo.
echo ══════════════════════════════════════════════════════════════
echo.
pause

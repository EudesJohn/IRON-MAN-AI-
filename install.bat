@echo off
chcp 65001 >nul
title IRON MAN AI - Installation / Mise a jour

echo.
echo     ========================================
echo               IRON MAN AI
echo         Installation Windows
echo        Fait par Eudes Johnson
echo     ========================================
echo.

set INSTALL_DIR=%USERPROFILE%\iron-man-ai
set BIN_DIR=%USERPROFILE%\bin
set PYTHON_DIR=%INSTALL_DIR%\venv

:: ─── Verifier si c'est une mise a jour ──────────────────────
if "%1"=="--update" goto :update
if "%1"=="-u" goto :update
if "%1"=="install" goto :install

:: ─── Par defaut : installation ──────────────────────────────
:install

:: ─── [1/6] Verification de Python ─────────────────────────
echo   [1/6] Verification de Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERREUR] Python n'est pas installe !
    echo.
    echo   Telechargez Python depuis :
    echo     https://www.python.org/downloads/
    echo   Cochez "Add Python to PATH" lors de l'installation !
    echo.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version
echo   OK Python detecte

:: ─── [2/6] Verification de Git ────────────────────────────
echo.
echo   [2/6] Verification de Git...
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERREUR] Git n'est pas installe !
    echo   Telechargez Git depuis : https://git-scm.com/download/win
    start https://git-scm.com/download/win
    pause
    exit /b 1
)
echo   OK Git detecte

:: ─── [3/6] Clone ou mise a jour du depot ──────────────────
echo.
echo   [3/6] Preparation du projet...
if exist "%INSTALL_DIR%" (
    echo   Projet existant detecte — mise a jour...
    cd /d "%INSTALL_DIR%"
    git pull origin main >nul 2>&1
    echo   OK Mis a jour
) else (
    echo   Clonage du depot...
    git clone https://github.com/EudesJohn/IRON-MAN-AI-.git "%INSTALL_DIR%"
    cd /d "%INSTALL_DIR%"
)

:: Verifier que codescan existe
if not exist "%INSTALL_DIR%\codescan" (
    echo   [ERREUR] Le dossier codescan n'existe pas dans %INSTALL_DIR%
    echo   Verifiez que le clonage a reussi.
    pause
    exit /b 1
)

cd /d "%INSTALL_DIR%\codescan"
echo   OK Projet pret dans %INSTALL_DIR%\codescan

:: ─── [4/6] Virtualenv + dependances Python ─────────────────
echo.
echo   [4/6] Installation des dependances Python...
if not exist "%PYTHON_DIR%" (
    python -m venv "%PYTHON_DIR%" 2>nul
)
call "%PYTHON_DIR%\Scripts\activate.bat"

pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt >nul 2>&1
pip install requests beautifulsoup4 pystache fpdf2 >nul 2>&1
echo   OK Dependances Python installees

:: ─── [5/6] Outils systeme ─────────────────────────────────
echo.
echo   [5/6] Verification des outils...
echo   Certains outils (nmap, sqlmap) necessitent une installation manuelle sur Windows
echo   Telechargez nmap : https://nmap.org/download.html
echo   OK Outils Python installes

:: ─── [6/6] Creer la commande globale ──────────────────────
echo.
echo   [6/6] Configuration de la commande 'ironman'...

:: Creer le repertoire bin
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

:: Creer le script ironman.bat
> "%BIN_DIR%\ironman.bat" (
    echo @echo off
    echo cd /d "%INSTALL_DIR%"
    echo call "%PYTHON_DIR%\Scripts\activate.bat"
    echo.
    echo if "%%1"=="" ^(
    echo     python "%INSTALL_DIR%\codescan\ironman_menu.py"
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%1"=="--update" ^(
    echo     echo Mise a jour en cours...
    echo     cd /d "%INSTALL_DIR%"
    echo     git pull origin main
    echo     pip install -r codescan\requirements.txt
    echo     echo OK Mis a jour !
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%1"=="--uninstall" ^(
    echo     echo Suppression d'IRON MAN AI...
    echo     rmdir /s /q "%INSTALL_DIR%"
    echo     del "%BIN_DIR%\ironman.bat"
    echo     echo OK Desinstalle !
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%1"=="--scan" ^(
    echo     python "%INSTALL_DIR%\codescan\kali_scan.py" --url %%2 --authorized --attack --pdf
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%1"=="--exploit" ^(
    echo     python "%INSTALL_DIR%\codescan\exploit_now.py" "%%2" --authorized
    echo     goto :eof
    echo ^)
    echo.
    echo if "%%1"=="--help" ^(
    echo     echo.
    echo     echo   IRON MAN AI — Aide
    echo     echo   ═══════════════════════════════════════
    echo     echo.
    echo     echo   ironman                    Lancer le menu interactif
    echo     echo   ironman --scan ^<url^>       Scan web rapide
    echo     echo   ironman --exploit ^<url^>    Exploitation directe
    echo     echo   ironman --update           Mettre a jour
    echo     echo   ironman --uninstall        Desinstaller
    echo     echo   ironman --help             Aide
    echo     echo.
    echo     goto :eof
    echo ^)
    echo.
    echo echo [ERREUR] Commande inconnue : %%1
    echo echo Tapez : ironman --help
)

:: Ajouter le repertoire bin au PATH
setx PATH "%PATH%;%BIN_DIR%" >nul 2>&1

echo   OK Commande 'ironman' creee dans %BIN_DIR%

:: ─── Finalisation ─────────────────────────────────────────
if not exist "%INSTALL_DIR%\rapports" mkdir "%INSTALL_DIR%\rapports"

echo.
echo ══════════════════════════════════════════════════════════════
echo   OK IRON MAN AI installe avec succes !
echo.
echo   Pour commencer, rouvrez un NOUVEAU terminal et tapez :
echo.
echo     ironman
echo.
echo   Autres commandes :
echo.
echo     ironman --scan ^<url^>        Scan web rapide
echo     ironman --exploit ^<url^>     Exploitation directe
echo     ironman --update            Mettre a jour
echo     ironman --uninstall         Desinstaller
echo     ironman --help              Aide
echo.
echo ══════════════════════════════════════════════════════════════
echo.
pause
exit /b 0

:: ─── MISE A JOUR ───────────────────────────────────────────
:update
echo.
echo   Mise a jour d'IRON MAN AI...
echo.

if not exist "%INSTALL_DIR%" (
    echo   [ERREUR] IRON MAN AI n'est pas installe !
    echo   Lancez l'installation d'abord.
    pause
    exit /b 1
)

cd /d "%INSTALL_DIR%"
echo   [1/3] Mise a jour du code source...
git pull origin main
if %errorlevel% neq 0 (
    echo   [ERREUR] Echec de la mise a jour Git
    pause
    exit /b 1
)
echo   OK Code source mis a jour

echo.
echo   [2/3] Mise a jour des dependances Python...
if not exist "%PYTHON_DIR%" (
    python -m venv "%PYTHON_DIR%" 2>nul
)
call "%PYTHON_DIR%\Scripts\activate.bat"
pip install --upgrade pip >nul 2>&1
pip install -r "%INSTALL_DIR%\codescan\requirements.txt" >nul 2>&1
echo   OK Dependances mises a jour

echo.
echo   [3/3] Verification des outils...
echo   OK Termine

echo.
echo ══════════════════════════════════════════════════════════════
echo   OK IRON MAN AI mis a jour avec succes !
echo.
echo   Version actuelle :
cd /d "%INSTALL_DIR%"
git log --oneline -1
echo.
echo ══════════════════════════════════════════════════════════════
echo.
pause
exit /b 0

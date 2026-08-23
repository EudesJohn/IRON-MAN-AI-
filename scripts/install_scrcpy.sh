#!/usr/bin/env bash
# Installation de scrcpy + adb + ffmpeg pour contrôler votre téléphone
# Android depuis votre PC (cadre : votre propre matériel).
#
# Usage :  bash scripts/install_scrcpy.sh
# Nécessite sudo sur Linux (mot de passe demandé une fois).
set -euo pipefail

echo "==> Vérification de la distribution..."

if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS
    if ! command -v brew >/dev/null 2>&1; then
        echo "Erreur : Homebrew requis (https://brew.sh)." >&2
        exit 1
    fi
    brew install scrcpy
    brew install --cask android-platform-tools
    echo "OK : scrcpy installé. Lancez 'adb devices' puis 'scrcpy'."
    exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
    # Debian / Ubuntu
    echo "==> Installation via apt (sudo requis) :"
    sudo apt-get update
    sudo apt-get install -y scrcpy adb ffmpeg
elif command -v dnf >/dev/null 2>&1; then
    # Fedora
    sudo dnf install -y scrcpy android-tools ffmpeg
elif command -v pacman >/dev/null 2>&1; then
    # Arch
    sudo pacman -Sy --noconfirm scrcpy android-tools ffmpeg
else
    echo "Distribution non reconnue. Voyez la doc officielle :" >&2
    echo "  https://github.com/Genymobile/scrcpy#get-the-app" >&2
    exit 1
fi

echo
echo "==> Vérification :"
adb version | head -1
scrcpy --version | head -1
echo
echo "OK. Branchez votre téléphone en USB (débogage USB activé),"
echo "acceptez l'invite sur l'écran, puis lancez :  scrcpy"

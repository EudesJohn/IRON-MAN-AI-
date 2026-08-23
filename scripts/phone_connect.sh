#!/usr/bin/env bash
# Aide à la connexion adb vers VOTRE téléphone Android (scrcpy).
#
# Usage :
#   bash scripts/phone_connect.sh usb
#   bash scripts/phone_connect.sh wifi 192.168.1.20:43211   # adb connect
#   bash scripts/phone_connect.sh tunnel user@monserveur     # reverse SSH
#
# Cadre : votre propre matériel. Voir docs/MANUEL_CONTROLE.md.
set -euo pipefail

if ! command -v adb >/dev/null 2>&1; then
    echo "Erreur : adb introuvable (bash scripts/install_scrcpy.sh)." >&2
    exit 1
fi

mode="${1:-usb}"

case "$mode" in
    usb)
        echo "==> Mode USB : liste des appareils"
        adb kill-server 2>/dev/null || true
        adb start-server
        adb devices
        echo
        echo "Si votre téléphone apparaît en « unauthorized » :"
        echo "  déverrouillez-le et acceptez l'invite « Autoriser le"
        echo "  débogage USB ? »."
        echo "Puis lancez :  scrcpy"
        ;;
    wifi)
        target="${2:-}"
        if [[ -z "$target" ]]; then
            echo "Usage : $0 wifi IP:PORT" >&2
            echo "Ex. :   $0 wifi 192.168.1.20:43211" >&2
            echo "(IP:PORT affiché dans Paramètres → Options développeur →"
            echo " Débogage sans fil ; pour Android 10- : adb tcpip 5555)" >&2
            exit 2
        fi
        echo "==> Connexion adb réseau à $target"
        adb connect "$target"
        adb devices
        echo
        echo "Puis lancez :  scrcpy --tcpip"
        ;;
    tunnel)
        server="${2:-}"
        if [[ -z "$server" ]]; then
            echo "Usage : $0 tunnel user@monserveur" >&2
            echo "Ouvre un tunnel SSH sortant : expose le port adb local"
            echo "du téléphone sur votre serveur (voir le manuel §5)." >&2
            exit 2
        fi
        echo "==> Tunnel SSH sortant vers $server (Ctrl+C pour couper)"
        echo "    Depuis n'importe où : ssh $server -L 5555:127.0.0.1:5555"
        echo "    puis : scrcpy --tcpip=127.0.0.1:5555"
        exec ssh -N -R 5555:127.0.0.1:5555 "$server"
        ;;
    *)
        echo "Usage : $0 {usb|wifi IP:PORT|tunnel user@serveur}" >&2
        exit 2
        ;;
esac

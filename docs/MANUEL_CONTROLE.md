# Manuel — Contrôler votre téléphone Android depuis votre PC

Voir l'écran de **votre** téléphone en temps réel et le piloter depuis
votre ordinateur : à la maison (USB ou WiFi) ou **à distance** (depuis
n'importe où dans le monde, via un tunnel sécurisé). La solution
principale est **scrcpy** (open-source, gratuit) + **adb**.

> ⚠️ **Cadre strict.** Ce manuel ne s'applique qu'à **votre propre téléphone**
> (ou un appareil dont vous avez la garde avec accord).
> Le débogage USB exige l'accès à l'écran de l'appareil : c'est la
> garantie que c'est le vôtre. Installer un accès distant sur le
> téléphone de quelqu'un d'autre sans son consentement est un délit
> (espionnage, accès non autorisé) — hors de propos ici.

---

## 1. Prérequis

- **adb** : `sudo apt-get install -y adb` (Linux) · `brew install
  android-platform-tools` (macOS) · [outils plateforme
  Google](https://developer.android.com/studio#command-line-tools)
  (Windows).
- **scrcpy** : voir [§ 2 Installation](#2-installation).
- Votre téléphone en **débogage USB** :
  1. Paramètres → À propos → tapez 7 fois sur « Numéro de build » ;
  2. Paramètres → Options développeur → activez **Débogage USB** ;
  3. Acceptez l'invite « Autoriser le débogage USB ? » sur l'écran
     (cochez « Toujours autoriser »).

---

## 2. Installation

### Linux (Debian/Ubuntu)

```bash
bash scripts/install_scrcpy.sh        # installe scrcpy + adb + ffmpeg (sudo)
```

### macOS

```bash
brew install scrcpy
brew install --cask android-platform-tools
```

### Windows

Téléchargez le binaire sur
<https://github.com/Genymobile/scrcpy/releases> (fichier
`scrcpy-win64-vX.Y.zip`), décompressez-le, puis lancez `scrcpy.exe`.

Vérifiez :

```bash
adb devices        # votre téléphone doit apparaître comme « device »
scrcpy --version
```

---

## 3. Mode local — USB (le plus simple)

1. Branchez le téléphone en USB (débogage USB activé).
2. `adb devices` → votre téléphone apparaît en « device ».
3. Lancez :

```bash
scrcpy
```

L'écran du téléphone s'affiche dans une fenêtre. **Souris = toucher**,
**clavier = saisie**, glisser-déposer = transfert de fichiers, `Ctrl+C`
= copier, `Ctrl+V` = coller, `Ctrl+S` = capture d'écran, `Ctrl+O` =
écran éteint (mode économie), `Ctrl+X` = verrouiller l'écran.

---

## 4. Mode local — WiFi (même réseau)

### Android 11 et plus (appairage sans fil)

1. Téléphone : Paramètres → Options développeur → **Appairage sans fil**
   (dans « Débogage sans fil »). Notez l'**adresse IP:port** et le
   **code d'appairage** affichés.
2. Sur le PC :

```bash
adb pair IP:PORT          # puis saisissez le code d'appairage
adb connect IP:PORT
scrcpy --tcpip
```

### Android 10 et moins (adb tcpip)

```bash
adb devices                        # téléphone en USB
adb tcpip 5555                     # active adb réseau (1 fois)
# débranchez le câble, puis :
adb connect IP_DU_TELEPHONE:5555
scrcpy --tcpip
```

> 🔒 Après usage : `adb disconnect` et réactivez le débogage USB filaire
> uniquement si nécessaire. Ne laissez **jamais** adb réseau actif sur un
> réseau public (café, hôtel) : n'importe qui sur ce réseau pourrait
> tenter de s'y connecter.

---

## 5. Mode distant — depuis n'importe où dans le monde

Principe : le téléphone reste **chez vous**, relié en USB (ou WiFi) à une
machine allumée en permanence (PC ou mini-PC). Cette machine ouvre un
**tunnel SSH sortant** vers un petit serveur que vous possédez (VPS à
~3 €/mois, ou un Raspberry Pi chez vous si vous avez une IP fixe/DNS
dynamique). De n'importe où, vous vous connectez à votre serveur et
pilotez le téléphone.

```
Votre PC (où que vous soyez)
   │  ssh user@monserveur
   ▼
Serveur (VPS) ◄────── tunnel SSH sortant (reverse) ────── machine à la maison
   ▲                                                        │ USB/WiFi
   └──────────────────────────────────────────────────────► téléphone (adb :5555)
```

### Étape 1 — machine à la maison (une seule fois)

```bash
# 1. Téléphone branché en USB, débogage USB activé
adb tcpip 5555
adb connect 127.0.0.1:5555        # adb local (sans le câble, en WiFi maison)

# 2. Clé SSH (une seule fois)
ssh-keygen -t ed25519
ssh-copy-id user@monserveur

# 3. Tunnel permanent (reverse) : expose le port adb local sur le serveur
ssh -N -R 5555:127.0.0.1:5555 user@monserveur
# → lancez-le via systemd/tmux pour qu'il survive aux déconnexions.
```

### Étape 2 — depuis n'importe où

```bash
# Sur VOTRE PC portable, en voyage :
ssh user@monserveur -L 5555:127.0.0.1:5555   # terminal 1 (gardez ouvert)
scrcpy --tcpip=127.0.0.1:5555               # terminal 2 : pilotez le téléphone
```

### Alternative : WireGuard (VPN privé)

Si vous avez un VPS, installez **WireGuard** (serveur sur le VPS, client
sur votre PC) : le téléphone (via la machine à la maison) devient
accessible comme un appareil du VPN, sans exposer de port. Plus simple à
maintenir, chiffré de bout en bout.

### Sécurité (non négociable)

- **Jamais** d'exposition directe d'adb sur Internet (pas de port 5555
  ouvert publiquement) — toujours derrière un tunnel SSH ou un VPN.
- **Clés SSH uniquement** (`PasswordAuthentication no` sur le serveur),
  pas de mot de passe.
- Activez le **verrou d'écran** du téléphone et le chiffrement : le
  tunnel ne sert à rien si l'appareil est lui-même vulnérable.
- Désactivez le débogage USB / adb réseau quand vous n'en avez pas besoin.

---

## 6. Dépannage

| Problème | Cause | Solution |
|---|---|---|
| `adb devices` vide | débogage USB off ou invite refusée | Activez le débogage USB, acceptez l'invite, `adb kill-server` |
| « device unauthorized » | clé de confiance non acceptée | Décochez « Toujours autoriser » et re-acceptez |
| `adb connect` échoue | IP erronée ou téléphone non appairable | Vérifiez l'IP dans les options développeur ; Android 11+ : appairage |
| scrcpy lent en WiFi | réseau saturé | Privilégiez le USB ; `scrcpy --max-size 1024 --max-fps 30` |
| écran noir | écran verrouillé ou vidéo non décodée | Déverrouillez le téléphone ; installez ffmpeg |
| tunnel distant coupé | déconnexion SSH | Utilisez `autossh` ou un service systemd avec redémarrage |

---

## 7. Limites (honnêteté technique)

- scrcpy ne fonctionne que sur des appareils **avec débogage USB actif**
  (donc les vôtres). Il ne contourne aucun verrou.
- En mode distant, le téléphone doit rester allumé, chargé et relié à la
  machine à la maison (ou rester connecté en WiFi).
- La latence distante dépend de votre connexion ; le USB reste le plus
  fluide.
- Pour localiser ou verrouiller un téléphone **perdu**, utilisez
  **Google Find My Device** (officiel) — scrcpy ne s'y substitue pas.

---

*Cadre : votre propre matériel. `adb` + `scrcpy` en local, tunnel SSH ou
WireGuard pour le distant.*

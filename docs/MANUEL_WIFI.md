# Manuel d'utilisation — IRON MAN AI : Audit WiFi

Le module **WiFi** de IRON MAN AI permet de tester la sécurité d'un réseau
WiFi que vous possédez (ou pour lequel vous avez une autorisation écrite) :
scan des réseaux à portée, capture et crack du handshake WPA2, audit WPS,
recommandations de durcissement.

> ⚠️ **Sécurité et éthique.** Ce module ne s'utilise que sur votre propre
> réseau ou sur un réseau que vous êtes **explicitement autorisé** à
> tester (contrat de pentest, réseau d'entreprise mandaté…). Le flag
> `--authorized` est obligatoire.
> **Cracker le WiFi d'un inconnu est illégal** et n'est pas couvert par
> cet outil. Le test de déauthentification perturbe le réseau : faites-le
> uniquement sur votre matériel et prévenez les utilisateurs.

---

## 1. Prérequis

- **Python 3.10+** (le cœur est en stdlib, aucune dépendance).
- **Kali Linux** avec une **carte WiFi compatible mode monitor**.
- Les outils **aircrack-ng** (airmon-ng, airodump-ng, aireplay-ng,
  aircrack-ng) : `sudo apt-get install -y aircrack-ng`
- Optionnel : `reaver` / `bully` / `pixiewps` (audit WPS), `wash`,
  `hashcat` ou `john` (crack accéléré).

Vérifiez la présence des outils (aucune action sur le réseau) :

```bash
cd /chemin/codescan
python mobile_scan.py --wifi --check
```

---

## 2. Première utilisation : scanner les réseaux à portée

```bash
# Lister les interfaces WiFi disponibles
iw dev

# Lancer le scan (30 s par défaut)
sudo python mobile_scan.py --wifi --interface wlan0 --authorized
```

Le script active le **mode monitor** sur l'interface, scanne pendant la
durée demandée puis affiche les réseaux détectés, triés par force de
signal :

```
  1. MonReseau                  AA:BB:CC:DD:EE:FF  ch 6   -45 dBm  WPA2
  2. Voisin_WPA                11:22:33:44:55:66  ch 11  -70 dBm  WPA
```

- `--scan-time N` : durée du scan en secondes (30 par défaut).
- L'interface est **automatiquement restaurée** à la fin (mode managed,
  NetworkManager relancé).

> 💡 **Conseil d'utilisation efficace** : lancez le scan en premier, puis
> relevez le **BSSID** et le **canal** du réseau que vous voulez tester
> (le vôtre). Ces deux valeurs servent aux étapes suivantes.

---

## 3. Tester la robustesse du mot de passe : capture + crack WPA2

La méthode standard pour vérifier qu'un mot de passe WiFi n'est pas
faible :

```bash
sudo python mobile_scan.py --wifi --interface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF --ssid MonReseau --channel 6 \
    --crack --authorized
```

Ce que fait la commande :

1. **Capture ciblée** : airodump-ng écoute le canal du réseau cible.
2. **Déauthentification** : un client connecté est déconnecté (5 paquets
   deauth) pour forcer sa reconnexion — c'est pendant cette reconnexion
   que le handshake WPA2 est capturé.
3. **Crack par dictionnaire** : aircrack-ng essaie chaque mot de passe de
   la wordlist (rockyou par défaut si présente) contre le handshake.

Options utiles :

| Option | Effet |
|---|---|
| `--capture-time N` | Durée de capture (120 s par défaut) |
| `-w /chemin/wordlist.txt` | Dictionnaire à utiliser |
| `--method john` / `--method hashcat` | Autre outil de crack |
| `--wps` | Ajoute un test de vulnérabilité WPS (reaver) |

Si le mot de passe est trouvé, il s'affiche :

```
[wifi] 🎉 MOT DE PASSE TROUVÉ : motdepassefaible123
```

> 💡 **Conseil d'utilisation efficace** : si la capture échoue
> (« Aucun handshake »), c'est qu'aucun client ne s'est reconnecté.
> Relancez avec un client actif (téléphone en veille se reconnecte
> souvent tout seul) ou augmentez `--capture-time`. Pour vos tests,
> utilisez une wordlist adaptée (rockyou pour les mots de passe
> courants, ou une wordlist maison avec vos anciens mots de passe).

---

## 4. Audit WPS

Le WPS (Wi-Fi Protected Setup) est une porte d'entrée connue : un PIN
faible ou une implémentation buguée permet de retrouver la clé WPA2 sans
dictionnaire.

```bash
sudo python mobile_scan.py --wifi --interface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --wps --authorized
```

- `reaver` tente les PIN possibles (peut prendre du temps — borné à
  30 min par tentative).
- Si le WPS est vulnérable, le PIN (et parfois le mot de passe) s'affiche.
- Si le routeur **verrouille** le WPS après plusieurs essais, l'outil le
  signale.

> 💡 **Conseil** : l'audit WPS est bruyant (le routeur peut se verrouiller
> ou se redémarrer). À n'utiliser que sur votre propre équipement, en
> dehors des heures d'usage.

---

## 5. Simuler sans rien casser : le mode dry-run

Avant chaque vraie campagne, visualisez **exactement** les commandes qui
seraient exécutées :

```bash
python mobile_scan.py --wifi --bssid AA:BB:CC:DD:EE:FF --crack --wps \
    --authorized --dry-run
```

Aucun paquet n'est émis : utile pour vérifier la ligne de commande et
pour la documentation.

---

## 6. Rapport de l'audit

Ajoutez `-o rapport` pour produire un **rapport JSON + HTML** consolidé
(réseaux, handshake, crack, WPS, recommandations) :

```bash
sudo python mobile_scan.py --wifi --bssid AA:BB:CC:DD:EE:FF --crack \
    --authorized -o /tmp/rapport_wifi
# → /tmp/rapport_wifi.json + /tmp/rapport_wifi.html
```

Le rapport se termine par des **recommandations de sécurité** : mot de
passe plus long, WPS désactivé, WPA3 si disponible, désactivation du
SSID broadcast, etc.

---

## 7. Bonnes pratiques pour une utilisation efficace

1. **Cadre légal d'abord** : réseau possédé ou autorisation écrite.
   Documentez le périmètre avant de commencer.
2. **Interface propre** : utilisez une carte USB dédiée (Alfa AWUS036ACH
   ou similaire) — les cartes internes supportent mal le mode monitor.
3. **Antenne et position** : rapprochez-vous du routeur testé pour un
   signal stable (> -70 dBm) : le handshake se capture beaucoup plus vite.
4. **Wordlists adaptées** : rockyou pour les mots de passe courants ;
   pour tester la politique d'un réseau, créez une wordlist dédiée
   (années, prénoms, marques…).
5. **Minimisez l'impact** : les deauth et reaver perturbent le réseau —
   testez en dehors des heures d'utilisation.
6. **Vérifiez les recommandations** : changez le mot de passe, désactivez
   WPS, passez en WPA3/WPA2-AES (jamais TKIP), activez le filtrage des
   invités.

---

## 8. Dépannage

| Problème | Cause probable | Solution |
|---|---|---|
| `Interface monitor non active` | mode monitor non démarré | Vérifiez que vous êtes root (`sudo`) et que la carte supporte le monitor (`iw list`) |
| Aucun réseau détecté | mauvaise interface ou canal | Relancez avec `--interface` correct ; essayez `airodump-ng <iface>` à la main |
| Aucun handshake | aucun client actif | Attendez une reconnexion, augmentez `--capture-time` |
| `Aucune wordlist trouvée` | pas de wordlist Kali | Installez rockyou : `sudo apt-get install -y wordlists` puis décompressez `/usr/share/wordlists/rockyou.txt.gz` |
| WPS verrouillé | trop de tentatives | Patientez (verrou temporaire) ; le test WPS est à faire une seule fois |

"""Paquet `kali` : orchestration de l'audit web complet « IRON MAN AI ».

Depuis Kali Linux, un audit complet d'un site web enchaîne tous les outils
disponibles (nmap, nikto, whatweb, gobuster, dirsearch, sslscan, nuclei,
wafw00f, dnsrecon puis — en mode maximal — sqlmap, xsstrike, commix, hydra),
avec un préflight qui vérifie la présence des binaires et affiche la
commande d'installation des paquets manquants. Le résultat est produit en
JSON, HTML et **PDF** (générateur stdlib, aucun rendu navigateur requis).

Deux paliers d'agressivité :
  - `web`   (défaut) : outils non invasifs de reconnaissance/vulnérabilités ;
  - `attack` (--attack/) outils invasifs (sqlmap, xsstrike, commix,
    hydra) réservés aux cibles explicitement autorisées. Le mode `--full`
    (alias : `ironman.py`) les active tous, sans limite de temps, avec la
    wordlist complète et un scan nmap maximal.

Le module ne dépend que de bibliothèque standard Python (subprocess,
shutil, re, urllib.parse, zlib) et réutilise `scanner.models.Finding`,
`scanner.scorer` et les rapports `reports/*`.
"""

__version__ = "1.4.0"
TOOL_NAME = "IRON MAN AI"
TOOL_FULL = "IRON MAN AI — Audit Kali"
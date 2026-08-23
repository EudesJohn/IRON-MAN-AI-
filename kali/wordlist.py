"""Listes de chemins par défaut pour le fuzz d'annuaire (gobuster/dirsearch).

La préférence est donnée à la grosse wordlist de Kali quand elle existe
(`/usr/share/wordlists/dirb/common.txt`) ; sinon on utilise une mini-liste
embarquée, suffisante pour un scan rapide et légal d'un site web — le but
est de garder des scans rapides et non bruyants.
"""

import os

KALI_COMMON = "/usr/share/wordlists/dirb/common.txt"

# Mini-liste embarquée (stdlib) — chemins classiques, sans fuzz lourd.
EMBEDDED = (
    "/", "/index", "/index.php", "/index.html", "/robots.txt",
    "/sitemap.xml", "/admin", "/login", "/search", "/api", "/health",
    "/status", "/swagger", "/debug", "/console", "/shell", "/.git/HEAD",
    "/backup", "/config", "/.env", "/README", "/phpinfo.php",
)

# Toutes wordlist entieres (limite par mesure de sécurité : on ne propage
# pas des milliers de requêtes dans un gestionnaire HTTP simple).
MAX_WORDS = 200


def resolve_wordlist(preferred: str = KALI_COMMON, max_words: int = MAX_WORDS) -> list:
    """Renvoie la liste de mots à utiliser (fichier si lisible, sinon embarquée).

    `max_words=None` renvoie la wordlist **complète** du fichier Kali
    (mode maximal d'IRON MAN AI) : plus aucune limite sur le nombre de
    requêtes propagées à la cible autorisée.
    """
    try:
        with open(preferred, "r", encoding="utf-8", errors="replace") as fh:
            words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if words:
            return words if max_words is None else words[:max_words]
    except OSError:
        pass
    return EMBEDDED if max_words is None else list(EMBEDDED[:max_words])


def wordlist_path(preferred: str = KALI_COMMON, tmp_dir: str = None,
                  max_words: int = MAX_WORDS) -> str:
    """Chemin d'un fichier wordlist exploitable par gobuster/dirsearch.

    Les outils exigent un *fichier*, pas une liste : on préfère la wordlist
    Kali quand elle existe ; sinon on matérialise la mini-liste embarquée
    dans `<tmp_dir>/wordlist.txt` et on renvoie ce chemin.

    `max_words=None` (mode maximal) garde la wordlist complète, sans limite.
    """
    if os.path.isfile(preferred):
        return preferred
    if tmp_dir:
        words = resolve_wordlist(preferred, max_words=max_words)
        path = os.path.join(tmp_dir, "wordlist.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(words) + "\n")
        return path
    return preferred
"""Extraction de la cible depuis une URL (stdlib uniquement).

Décompose une URL d'entrée en structure réutilisable par les exécuteurs
d'outils : schéma, hôte, port, chemin, domaine (sans www) et URL complète.
"""

from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def split_target(url: str) -> dict:
    """Décompose `url` et renvoie un dict normalisé.

    Accepte une URL avec ou sans `http://` préfixé. Les champs produits :
      scheme, host, port, path, domain, url (forme normale).
    """
    if url is None:
        url = ""
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or ""
    if not host:
        host = parts.netloc or ""
    port = parts.port or _DEFAULT_PORTS.get(scheme, 80)
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    domain = host[4:] if host.lower().startswith("www.") else host
    netloc = host if ((scheme, port) in (("http", 80), ("https", 443))) \
        else f"{host}:{port}"
    normal = urlunsplit((scheme, netloc, path, parts.query, ""))
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "domain": domain,
        "url": normal,
    }


def netloc(target: dict) -> str:
    """Hôte:port si non-standard, sinon hôte seul (pour hydra, sslscan…)."""
    if (target["scheme"], target["port"]) in (("http", 80), ("https", 443)):
        return target["host"]
    return f"{target['host']}:{target['port']}"
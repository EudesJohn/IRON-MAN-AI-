"""Registre des outils du mode WebScan Kali.

Chaque entrée décrit un outil de sécurité : binaire (pour `shutil.which`),
paquet apt Kali à installer, palier d'agressivité ("web" ou "attack"),
descriptif français et constructeur de commande. Les commandes sont non
interactives et sûres : wordlists limitées, top-ports limité, timeouts.

Les outils invasifs (sqlmap, xsstrike, commix, hydra) ne sont lancés que
lorsque le palier "attack" est explicitement demandé.
"""

from .urls import netloc
from .wordlist import resolve_wordlist

# Wordlist par défaut pour gobuster / dirsearch (fichier Kali, sinon une
# mini-liste embarquée résolue par `resolve_wordlist`).
KALI_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def _maximal(ctx) -> bool:
    """Le mode maximal (--full) est-il actif ? (aucune limite, tout à fond)."""
    return bool(ctx.get("maximal"))


def _cmd_nmap(target, ctx):
    if _maximal(ctx):
        # Scan maximal : tous les ports (-p-), scripts par défaut (-sC).
        return ["nmap", "-sV", "-Pn", "-p-", "-sC", target["host"]]
    return ["nmap", "-sV", "-Pn", "--top-ports", "100", target["host"]]


def _cmd_nikto(target, ctx):
    return ["nikto", "-h", target["url"], "-maxtime", str(ctx.get("max_time", 120)),
            "-no-cgi"]


def _cmd_whatweb(target, ctx):
    return ["whatweb", target["url"], "--log-json", ctx["tmp"] + "/whatweb.json"]


def _cmd_gobuster(target, ctx):
    threads = "64" if _maximal(ctx) else "16"
    return ["gobuster", "dir", "-u", target["url"], "-w",
            ctx["wordlist"], "-t", threads, "-q"]


def _cmd_dirsearch(target, ctx):
    threads = ["--threads", "30"] if _maximal(ctx) else []
    return ["dirsearch", "-u", target["url"], "-w", ctx["wordlist"],
            "-o", ctx["tmp"] + "/dirsearch.json"] + threads


def _cmd_sslscan(target, ctx):
    return ["sslscan", "--no-colour", netloc(target)]


def _cmd_nuclei(target, ctx):
    return ["nuclei", "-u", target["url"], "-jsonl", "-duc", "-nh",
            "-severity", "low,medium,high,critical",
            "-o", ctx["tmp"] + "/nuclei.jsonl"]


def _cmd_wafw00f(target, ctx):
    return ["wafw00f", target["url"]]


def _cmd_dnsrecon(target, ctx):
    return ["dnsrecon", "-d", target["domain"], "-t", "std"]


# --- Palier attack (uniquement avec --attack) --------------------------------

def _cmd_sqlmap(target, ctx):
    if _maximal(ctx):
        # Détection la plus poussée : --level 3 --risk 3 (lent mais exhaustif).
        return ["sqlmap", "-u", target["url"], "--batch", "--forms", "--crawl", "3",
                "-t", "1", "--risk", "3", "--level", "3",
                "--output-dir", ctx["tmp"] + "/sqlmap"]
    return ["sqlmap", "-u", target["url"], "--batch", "--forms", "--crawl", "2",
            "-t", "1", "--risk", "1", "--level", "1",
            "--output-dir", ctx["tmp"] + "/sqlmap"]


def _cmd_xsstrike(target, ctx):
    return ["xsstrike", "-u", target["url"], "--crawl", "--loglevel", "ERROR"]


def _cmd_commix(target, ctx):
    level = "3" if _maximal(ctx) else "1"
    return ["commix", "-u", target["url"], "--batch", "--level", level]


def _cmd_hydra(target, ctx):
    # hydra exige des wordlists explicites : sans elles, on saute l'outil.
    users = ctx.get("hydra_users")
    passes = ctx.get("hydra_passwords")
    if not users or not passes:
        return None  # signale à l'appelant « désactivé par défaut »
    return ["hydra", "-L", users, "-P", passes, netloc(target), "http-get", "/"]


# Registre principal ----------------------------------------------------------

# Champs : bin, apt (paquet Kali), tier (web|attack), purpose (FR),
# cmd (constructeur de commande), parser (nom du parseur dans parsers.py),
# timeout (secondes), applies (optionnel : cible -> bool).
TOOLS = {
    "nmap": {
        "bin": "nmap", "apt": "nmap", "tier": "web",
        "purpose": "Découverte des ports ouverts et versions de services",
        "cmd": _cmd_nmap, "parser": "nmap", "timeout": 240,
    },
    "nikto": {
        "bin": "nikto", "apt": "nikto", "tier": "web",
        "purpose": "Scanner de vulnérabilités web (Nikto)",
        "cmd": _cmd_nikto, "parser": "nikto", "timeout": 240,
    },
    "whatweb": {
        "bin": "whatweb", "apt": "whatweb", "tier": "web",
        "purpose": "Détection des technologies et serveur (WhatWeb)",
        "cmd": _cmd_whatweb, "parser": "whatweb", "timeout": 120,
    },
    "gobuster": {
        "bin": "gobuster", "apt": "gobuster", "tier": "web",
        "purpose": "Énumération de répertoires et fichiers (Gobuster)",
        "cmd": _cmd_gobuster, "parser": "gobuster", "timeout": 120,
    },
    "dirsearch": {
        "bin": "dirsearch", "apt": "dirsearch", "tier": "web",
        "purpose": "Énumération de chemins web (dirsearch)",
        "cmd": _cmd_dirsearch, "parser": "dirsearch", "timeout": 180,
    },
    "sslscan": {
        "bin": "sslscan", "apt": "sslscan", "tier": "web",
        "purpose": "Contrôle TLS/SSL (protocoles faibles, certificats)",
        "cmd": _cmd_sslscan, "parser": "sslscan", "timeout": 180,
        "applies": lambda t: t["scheme"] == "https",
    },
    "nuclei": {
        "bin": "nuclei", "apt": "nuclei", "tier": "web",
        "purpose": "Scanner de vulnérabilités (nuclei, templates)",
        "cmd": _cmd_nuclei, "parser": "nuclei", "timeout": 300,
    },
    "wafw00f": {
        "bin": "wafw00f", "apt": "wafw00f", "tier": "web",
        "purpose": "Détection de pare-feu applicatif (WAF)",
        "cmd": _cmd_wafw00f, "parser": "wafw00f", "timeout": 120,
    },
    "dnsrecon": {
        "bin": "dnsrecon", "apt": "dnsrecon", "tier": "web",
        "purpose": "Reconnaissance DNS (enregistrements)",
        "cmd": _cmd_dnsrecon, "parser": "dnsrecon", "timeout": 120,
    },
    # --- Palier attack ------------------------------------------------------
    "sqlmap": {
        "bin": "sqlmap", "apt": "sqlmap", "tier": "attack",
        "purpose": "Détection d'injection SQL (sqlmap, mode --batch)",
        "cmd": _cmd_sqlmap, "parser": "sqlmap", "timeout": 480,
    },
    "xsstrike": {
        "bin": "xsstrike", "apt": "xsstrike", "tier": "attack",
        "purpose": "Détection de XSS (XSS Strike)",
        "cmd": _cmd_xsstrike, "parser": "xsstrike", "timeout": 300,
    },
    "commix": {
        "bin": "commix", "apt": "commix", "tier": "attack",
        "purpose": "Détection d'injection de commandes OS (commix)",
        "cmd": _cmd_commix, "parser": "commix", "timeout": 300,
    },
    "hydra": {
        "bin": "hydra", "apt": "hydra", "tier": "attack",
        "purpose": "Vérification de mots de passe (hydra, wordlists requises)",
        "cmd": _cmd_hydra, "parser": "hydra", "timeout": 300,
    },
}

# Ordre d'exécution présenté dans la console et les rapports.
ORDER = ["nmap", "nikto", "whatweb", "gobuster", "dirsearch", "sslscan",
         "nuclei", "wafw00f", "dnsrecon", "sqlmap", "xsstrike", "commix",
         "hydra"]


def all_tools(attack: bool = False) -> list:
    """Renvoie les entrées (name, spec) des outils à lancer, dans l'ordre."""
    out = []
    for name in ORDER:
        spec = TOOLS.get(name)
        if not spec:
            continue
        if spec["tier"] == "attack" and not attack:
            continue
        out.append((name, spec))
    return out


def applies(tool, target: dict) -> bool:
    """L'outil est-il applicable à cette cible ? (faux → skip propre)."""
    return tool.get("applies", lambda t: True)(target)


def build_command(name: str, target: dict, tmp: str,
                  wordlist: str = None) -> list or None:
    """Construit la liste d'arguments argv de l'outil (None si non applicable).

    `wordlist` : chemin de la wordlist (gobuster/dirsearch) ou None pour
    utiliser celle de Kali par défaut.
    """
    tool = TOOLS.get(name)
    if not tool:
        return None
    ctx = {
        "tmp": tmp,
        "wordlist": wordlist or KALI_WORDLIST,
        "max_time": 120,
        "maximal": False,
        "hydra_users": None,
        "hydra_passwords": None,
    }
    return tool["cmd"](target, ctx)
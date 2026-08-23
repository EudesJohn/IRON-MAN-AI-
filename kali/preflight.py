"""Préflight du mode WebScan Kali : vérifie la présence des outils.

La commande « --check » affiche pour chaque outil du registre :
  - son binaire est-il trouvable (shutil.which) ;
  - s'il manque, le binaire de remplacement Windows (si disponible) ;
  - s'il manque, la commande d'installation selon l'OS (apt, choco, brew...).

Le préflight est non destructif : il n'installe rien, il veille à ce que
l'utilisateur ait bien tous les outils avant de lancer un scan.
"""

import os
import platform
import shutil
import sys

from .tools import all_tools, TOOLS

# ─── Détection OS ──────────────────────────────────────────────────────

def _detect_os():
    """Détecte l'OS courant et renvoie ('linux'|'windows'|'macos', nom_affiché)."""
    s = platform.system()
    if s == "Windows":
        return "windows", "Windows"
    elif s == "Darwin":
        return "macos", "macOS"
    else:
        return "linux", "Linux"


# ─── Alternatives Windows pour outils Linux ────────────────────────────
# Quand un outil Linux natif n'existe pas sur Windows, on utilise un
# outil Python qui fait le même travail.

_WINDOWS_ALTERNATIVES = {
    "nikto":    "whatweb",     # whatweb detecte les technologies
    "gobuster": "dirsearch",   # dirsearch enumere les chemins web
    "sslscan":  "whatweb",     # whatweb verifie les headers SSL/TLS
    "hydra":    None,          # pas d'alternative Python directe
}

# ─── Commandes d'installation par OS ───────────────────────────────────

_WINDOWS_INSTALL = {
    "nmap":     "winget install Insecure.Nmap",
    "nikto":    "Pas d'alternative Windows (whatweb utilise comme remplacement)",
    "whatweb":  "pip install whatweb",
    "gobuster": "Pas d'alternative Windows (dirsearch utilise comme remplacement)",
    "dirsearch":"pip install dirsearch",
    "sslscan":  "Pas d'alternative Windows (whatweb utilise comme remplacement)",
    "nuclei":   "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "wafw00f":  "pip install wafw00f",
    "dnsrecon": "pip install dnsrecon",
    "sqlmap":   "pip install sqlmap",
    "xsstrike": "pip install xsstrike",
    "commix":   "pip install commix",
    "hydra":    "Pas d'alternative Windows (xsstrike utilise pour le scan)",
}

_LINUX_INSTALL = {}

_MACOS_INSTALL = {
    "nmap":     "brew install nmap",
    "nikto":    "brew install nikto",
    "whatweb":  "brew install whatweb",
    "gobuster": "brew install gobuster",
    "dirsearch":"pip3 install dirsearch",
    "sslscan":  "brew install sslscan",
    "nuclei":   "brew install nuclei",
    "wafw00f":  "pip3 install wafw00f",
    "dnsrecon": "pip3 install dnsrecon",
    "sqlmap":   "brew install sqlmap",
    "xsstrike": "pip3 install xsstrike",
    "commix":   "pip3 install commix",
    "hydra":    "brew install hydra",
}

# ─── Core ───────────────────────────────────────────────────────────────

# Chemins Windows supplementaires ou les outils peuvent se trouver
_WINDOWS_EXTRA_PATHS = [
    os.path.join(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)"), "Nmap"),
    os.path.join(os.environ.get("PROGRAMFILES", "C:/Program Files"), "Nmap"),
    os.path.join(os.path.expanduser("~"), "go", "bin"),
    os.path.join(os.environ.get("PROGRAMDATA", "C:/ProgramData"), "chocolatey", "bin"),
]


def which(binary: str):
    """Renvoie le chemin trouvable de `binary` (ou None).

    Sur Windows, verifie aussi les chemins courants (nmap, go/bin, choco).
    """
    path = shutil.which(binary)
    if path:
        return path
    if platform.system() == "Windows":
        for extra_dir in _WINDOWS_EXTRA_PATHS:
            if not extra_dir or not os.path.isdir(extra_dir):
                continue
            candidate = os.path.join(extra_dir, binary + ".exe")
            if os.path.isfile(candidate):
                return candidate
            candidate = os.path.join(extra_dir, binary)
            if os.path.isfile(candidate):
                return candidate
        venv_scripts = os.path.join(sys.prefix, "Scripts") if hasattr(sys, 'prefix') else None
        if venv_scripts and os.path.isdir(venv_scripts):
            candidate = os.path.join(venv_scripts, binary)
            if os.path.isfile(candidate):
                return candidate
            candidate = os.path.join(venv_scripts, binary + ".exe")
            if os.path.isfile(candidate):
                return candidate
    return None


def check_tools(attack: bool = False) -> dict:
    """Vérifie la présence de chaque outil à lancer.

    Sur Windows, verifie aussi si une alternative Python est disponible
    (ex: whatweb pour nikto, dirsearch pour gobuster).

    Renvoie un dict {name: {"present": bool, "alt": str|None, ...}} pour les outils ordonnés.
    """
    os_id, _ = _detect_os()
    result = {}
    for name, spec in all_tools(attack=attack):
        path = which(spec["bin"])
        install_cmd = _get_install_cmd(name, spec["apt"], os_id)

        # Verifier l'alternative Windows si l'outil principal est absent
        alt_name = None
        alt_path = None
        if not path and os_id == "windows" and name in _WINDOWS_ALTERNATIVES:
            candidate = _WINDOWS_ALTERNATIVES[name]
            if candidate:
                alt_path = which(candidate)
                if alt_path:
                    alt_name = candidate

        result[name] = {
            "present": path is not None,
            "alt_present": alt_name is not None,
            "alt_name": alt_name,
            "alt_path": alt_path,
            "path": path,
            "bin": spec["bin"],
            "apt": spec["apt"],
            "install_cmd": install_cmd,
            "tier": spec["tier"],
            "purpose": spec["purpose"],
            "timeout": spec.get("timeout", 120),
        }
    return result


def _get_install_cmd(name: str, apt_pkg: str, os_id: str) -> str:
    """Retourne la commande d'installation adaptée à l'OS."""
    if os_id == "windows":
        return _WINDOWS_INSTALL.get(name, f"choco install {apt_pkg} -y")
    elif os_id == "macos":
        return _MACOS_INSTALL.get(name, f"brew install {apt_pkg}")
    else:
        return f"sudo apt-get install -y {apt_pkg}"


def missing_tools(status: dict) -> list:
    """Renvoie les entrées (name, info) dont le binaire est absent ET sans alternative."""
    return [(name, info) for name, info in status.items()
            if not info["present"] and not info.get("alt_present")]


def tools_needing_install(status: dict) -> list:
    """Renvoie les outils vraiment manquants (ni binaire ni alternative)."""
    return [(name, info) for name, info in status.items()
            if not info["present"] and not info.get("alt_present")]


def install_commands(missing: list) -> list:
    """Commande(s) à exécuter pour installer les outils manquants.

    Renvoie une liste de chaînes shell non exécutées ici (juridique : c'est
    l'utilisateur qui les lance, après confirmation).
    """
    if not missing:
        return []
    os_id, _ = _detect_os()

    if os_id == "windows":
        cmds = []
        has_choco = shutil.which("choco") is not None
        has_winget = shutil.which("winget") is not None

        if has_winget:
            for name, info in missing:
                if name in _WINDOWS_INSTALL and _WINDOWS_INSTALL[name].startswith("winget"):
                    cmds.append(_WINDOWS_INSTALL[name])

        if has_choco:
            choco_pkgs = []
            for name, info in missing:
                if name in _WINDOWS_INSTALL and _WINDOWS_INSTALL[name].startswith("choco"):
                    choco_pkgs.append(info["apt"])
            if choco_pkgs:
                cmds.append(f"choco install {' '.join(choco_pkgs)} -y")

        if not cmds:
            for name, info in missing:
                cmds.append(info["install_cmd"])

        return cmds

    elif os_id == "macos":
        pkgs = sorted({info["apt"] for _, info in missing})
        return [
            "brew update",
            "brew install " + " ".join(pkgs),
        ]
    else:
        pkgs = sorted({info["apt"] for _, info in missing})
        return [
            "sudo apt-get update",
            "sudo apt-get install -y " + " ".join(pkgs),
        ]


def format_status(status: dict, verbose: bool = False) -> str:
    """Formate le préflight en texte console (français, encodage sûr)."""
    os_id, os_name = _detect_os()
    lines = []
    lines.append(f"=== Preflight IRON MAN AI ({os_name}) ===")
    n_ok = 0
    n_alt = 0
    n_missing = 0
    for name, info in status.items():
        if info["present"]:
            marker = "[OK]"
            n_ok += 1
            detail = "present"
        elif info.get("alt_present"):
            marker = "[OK]"
            n_alt += 1
            detail = f"via {info['alt_name']}"
        else:
            marker = "[MANQUANT]"
            n_missing += 1
            detail = "absent"

        line = f"{marker:10s} {name:<10} {info['bin']:<12} {detail}"
        if not info["present"] and not info.get("alt_present"):
            line += f"   -> {info['install_cmd']}"
        if verbose:
            line += f"   ({info['purpose']})"
        lines.append(line)

    total = len(status)
    n_effective = n_ok + n_alt
    lines.append(f"-> {n_effective}/{total} outils operables ({n_ok} direct + {n_alt} via alternative).")
    if n_missing:
        cmds = install_commands(tools_needing_install(status))
        lines.append(f"-> {n_missing} outil(s) vraiment manquant(s) :")
        for c in cmds:
            lines.append(f"   {c}")

    return "\n".join(lines)


def print_preflight(status: dict, verbose: bool = False) -> None:
    """Affiche le préflight dans la console."""
    print(format_status(status, verbose))


def install_text(status: dict, verbose: bool = False) -> str:
    """Texte d'aide à l'installation."""
    os_id, os_name = _detect_os()
    really_missing = tools_needing_install(status)
    lines = [f"[Preflight IRON MAN AI - {os_name}]"]
    for name, info in status.items():
        if info["present"]:
            flag = "OK"
            suffix = ""
        elif info.get("alt_present"):
            flag = "OK"
            suffix = f" (alternative: {info['alt_name']})"
        else:
            flag = "MANQUANT"
            suffix = f" -> {info['install_cmd']}"
        lines.append(f"  {flag:8s} {name:<10} {info['bin']}{suffix}")

    n_effective = sum(1 for i in status.values() if i["present"] or i.get("alt_present"))
    lines.append(f"  {n_effective}/{len(status)} outils operables, "
                 f"{len(really_missing)} manquant(s).")

    if really_missing:
        os_id, _ = _detect_os()
        lines.append("")
        if os_id == "windows":
            lines.append("  Note : nikto/gobuster/sslscan/hydra ont des alternatives")
            lines.append("  Python installees automatiquement (whatweb, dirsearch, xsstrike).")
            lines.append("  Pour installer les outils Linux natifs :")
            lines.append("     1. Installer Chocolatey : https://chocolatey.org/install")
            lines.append("     2. Puis : choco install nikto gobuster sslscan hydra -y")
            lines.append("     3. Ou utiliser winget pour nmap : winget install Insecure.Nmap")
        elif os_id == "macos":
            lines.append("  Installation rapide sur macOS :")
            lines.append("     brew install " + " ".join(sorted({i["apt"] for _, i in really_missing})))
        else:
            lines.append("  Installation rapide sur Linux :")
            lines.append("     sudo apt-get update && sudo apt-get install -y " +
                         " ".join(sorted({i["apt"] for _, i in really_missing})))

    return "\n".join(lines)

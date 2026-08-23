"""Préflight du mode WebScan Kali : vérifie la présence des outils.

La commande « --check » affiche pour chaque outil du registre :
  - son binaire est-il trouvable (shutil.which) ;
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


# ─── Commandes d'installation par OS ───────────────────────────────────

# Commandes Windows (choco, winget, pip, ou téléchargement direct)
_WINDOWS_INSTALL = {
    "nmap":     "winget install Insecure.Nmap",
    "nikto":    "choco install nikto -y",
    "whatweb":  "pip install whatweb",
    "gobuster": "choco install gobuster -y",
    "dirsearch":"pip install dirsearch",
    "sslscan":  "choco install sslscan -y",
    "nuclei":   "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "wafw00f":  "pip install wafw00f",
    "dnsrecon": "pip install dnsrecon",
    "sqlmap":   "pip install sqlmap",
    "xsstrike": "pip install xsstrike",
    "commix":   "pip install commix",
    "hydra":    "choco install hydra -y",
}

# Commandes Linux (apt)
_LINUX_INSTALL = {}  # Construit automatiquement depuis TOOLS

# Commandes macOS (brew)
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

def which(binary: str):
    """Renvoie le chemin trouvable de `binary` (ou None).
    
    Sur Windows, verifie aussi les scripts sans .exe (pip installe
    parfois des scripts bash sans extension).
    """
    path = shutil.which(binary)
    if path:
        return path
    # Sur Windows, chercher aussi sans .exe (scripts pip)
    if platform.system() == "Windows":
        # Chercher dans le venv Scripts
        venv_scripts = os.path.join(sys.prefix, "Scripts") if hasattr(sys, 'prefix') else None
        if venv_scripts and os.path.isdir(venv_scripts):
            candidate = os.path.join(venv_scripts, binary)
            if os.path.isfile(candidate):
                return candidate
    return None


def check_tools(attack: bool = False) -> dict:
    """Vérifie la présence de chaque outil à lancer.

    Renvoie un dict {name: {"present": bool, "bin": str, "path": str|None,
    "install_cmd": str, "tier": str, "purpose": str}} pour les outils ordonnés.
    """
    os_id, _ = _detect_os()
    result = {}
    for name, spec in all_tools(attack=attack):
        path = shutil.which(spec["bin"])
        install_cmd = _get_install_cmd(name, spec["apt"], os_id)
        result[name] = {
            "present": path is not None,
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
    """Renvoie les entrées (name, info) dont le binaire est absent."""
    return [(name, info) for name, info in status.items() if not info["present"]]


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
        # Vérifier si choco et winget sont disponibles
        has_choco = shutil.which("choco") is not None
        has_winget = shutil.which("winget") is not None
        has_pip = shutil.which("pip") is not None

        if has_choco:
            choco_pkgs = []
            for name, info in missing:
                if name in _WINDOWS_INSTALL and _WINDOWS_INSTALL[name].startswith("choco"):
                    choco_pkgs.append(info["apt"])
            if choco_pkgs:
                cmds.append(f"choco install {' '.join(choco_pkgs)} -y")

        if has_winget:
            for name, info in missing:
                if name in _WINDOWS_INSTALL and _WINDOWS_INSTALL[name].startswith("winget"):
                    cmds.append(_WINDOWS_INSTALL[name])

        if has_pip:
            pip_pkgs = []
            for name, info in missing:
                if name in _WINDOWS_INSTALL and _WINDOWS_INSTALL[name].startswith("pip"):
                    pip_pkgs.append(info["apt"])
            if pip_pkgs:
                cmds.append(f"pip install {' '.join(pip_pkgs)}")

        if not cmds:
            # Fallback : afficher chaque commande individuellement
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
    lines.append(f"=== Préflight IRON MAN AI ({os_name}) ===")
    nmissing = 0
    for name, info in status.items():
        marker = "[OK]" if info["present"] else "[MANQUANT]"
        if not info["present"]:
            nmissing += 1
        line = (f"{marker} {name:<10} {info['bin']:<12} "
                f"{'present' if info['present'] else 'absent'}")
        if not info["present"]:
            line += f"   -> {info['install_cmd']}"
        if verbose:
            line += f"   ({info['purpose']})"
        lines.append(line)
    total = len(status)
    if nmissing:
        cmds = install_commands(missing_tools(status))
        lines.append(f"-> {total - nmissing}/{total} outils presents, "
                     f"{nmissing} manquant(s).")
        lines.append(f"Commande(s) a executer ({os_name}) :")
        for c in cmds:
            lines.append(f"   {c}")
    else:
        lines.append(f"-> Tous les outils ({total}) sont presents. C'est bon.")
    return "\n".join(lines)


def print_preflight(status: dict, verbose: bool = False) -> None:
    """Affiche le préflight dans la console."""
    print(install_text(status, verbose))


def install_text(status: dict, verbose: bool = False) -> str:
    """Texte d'aide à l'installation (identique à install_status)."""
    os_id, os_name = _detect_os()
    missing = missing_tools(status)
    lines = [f"[Preflight IRON MAN AI — {os_name}]"]
    for name, info in status.items():
        flag = "OK" if info["present"] else "MANQUANT"
        suffix = f" -> {info['install_cmd']}" if not info["present"] else ""
        lines.append(f"  {flag:8s} {name:<10} {info['bin']}{suffix}")
    lines.append(f"  {len(status) - len(missing)}/{len(status)} outils presents, "
                 f"{len(missing)} manquant(s).")

    if missing:
        os_id, _ = _detect_os()
        lines.append("")
        if os_id == "windows":
            lines.append("  Installation rapide sur Windows :")
            lines.append("     1. Installer Chocolatey : https://chocolatey.org/install")
            lines.append("     2. Puis copier/coller la commande ci-dessus")
            lines.append("     3. Ou utiliser winget pour nmap : winget install Insecure.Nmap")
        elif os_id == "macos":
            lines.append("  Installation rapide sur macOS :")
            lines.append("     brew install " + " ".join(sorted({i["apt"] for _, i in missing})))
        else:
            lines.append("  Installation rapide sur Linux :")
            lines.append("     sudo apt-get update && sudo apt-get install -y " +
                         " ".join(sorted({i["apt"] for _, i in missing})))

    return "\n".join(lines)

"""Préflight du mode WebScan Kali : vérifie la présence des outils.

La commande « --check » affiche pour chaque outil du registre :
  - son binaire est-il trouvable (shutil.which) ;
  - s'il manque, le paquet apt Kali à installer (commande à copier).

Le préflight est non destructif : il n'installe rien, il veille à ce que
l'utilisateur ait bien tous les outils avant de lancer un scan.
"""

import shutil

from .tools import all_tools, TOOLS


def which(binary: str):
    """Renvoie le chemin trouvable de `binary` (ou None)."""
    return shutil.which(binary)


def check_tools(attack: bool = False) -> dict:
    """Vérifie la présence de chaque outil à lancer.

    Renvoie un dict {name: {"present": bool, "bin": str, "path": str|None,
    "apt": str, "tier": str, "purpose": str}} pour les outils ordonnés.
    """
    result = {}
    for name, spec in all_tools(attack=attack):
        path = shutil.which(spec["bin"])
        result[name] = {
            "present": path is not None,
            "path": path,
            "bin": spec["bin"],
            "apt": spec["apt"],
            "tier": spec["tier"],
            "purpose": spec["purpose"],
            "timeout": spec.get("timeout", 120),
        }
    return result


def missing_tools(status: dict) -> list:
    """Renvoie les entrées (name, info) dont le binaire est absent."""
    return [(name, info) for name, info in status.items() if not info["present"]]


def install_commands(missing: list) -> list:
    """Commande(s) apt à exécuter pour installer les outils manquants.

    Renvoie une liste de chaînes shell non exécutées ici (juridique : c'est
    l'utilisateur qui les lance, après confirmation).
    """
    if not missing:
        return []
    pkgs = sorted({info["apt"] for _, info in missing})
    return [
        "sudo apt-get update",
        "sudo apt-get install -y " + " ".join(pkgs),
    ]


def format_status(status: dict, verbose: bool = False) -> str:
    """Formate le préflight en texte console (français, encodage sûr)."""
    lines = []
    lines.append("=== Préflight IRON MAN AI (Kali) ===")
    nmissing = 0
    for name, info in status.items():
        marker = "[OK]" if info["present"] else "[MANQUANT]"
        if not info["present"]:
            nmissing += 1
        line = (f"{marker} {name:<10} {info['apt']:<12} "
                f"{'-> present' if info['present'] else 'absent'}")
        if verbose:
            line += f"   ({info['purpose']})"
        lines.append(line)
    total = len(status)
    if nmissing:
        cmds = install_commands(missing_tools(status))
        lines.append(f"-> {total - nmissing}/{total} outils presents, "
                     f"{nmissing} manquant(s).")
        lines.append("Commande(s) a executer :")
        for c in cmds:
            lines.append("   " + c)
    else:
        lines.append(f"-> Tous les outils ({total}) sont presents. C'est bon.")
    return "\n".join(lines)


def print_preflight(status: dict, verbose: bool = False) -> None:
    """Affiche le préflight dans la console."""
    print(install_text(status, verbose))


def install_text(status: dict, verbose: bool = False) -> str:
    """Texte d'aide à l'installation (identique à install_status)."""
    missing = missing_tools(status)
    lines = ["[Preflight IRON MAN AI]"]
    for name, info in status.items():
        flag = "OK" if info["present"] else "MANQUANT"
        suffix = f" -> sudo apt-get install -y {info['apt']}" if not info["present"] else ""
        lines.append(f"  {flag:8s} {name:<10} {info['bin']}{suffix}")
    lines.append(f"  {len(status) - len(missing)}/{len(status)} outils presents, "
                 f"{len(missing)} manquant(s).")
    return "\n".join(lines)
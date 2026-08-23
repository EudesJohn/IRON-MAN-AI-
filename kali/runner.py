"""Exécution sûre des outils WebScan Kali.

Chaque outil est lancé avec un timeout et une capture complète de la sortie
(stdout + stderr) ; la sortie brute est conservée dans un fichier log par
outil (répertoire temporaire). Un outil qui n'existe pas ou qui timeout
n'arrête pas le scan : il est simplement enregistré comme défaillant.
"""

import os
import subprocess
import sys
import tempfile
from datetime import datetime


class ToolResult:
    """Résultat d'exécution d'un outil."""

    def __init__(self, name, cmd, rc=None, stdout="", stderr="", timed_out=False,
                 missing=False, duration=0.0):
        self.name = name
        self.cmd = list(cmd or [])
        self.rc = rc
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.timed_out = timed_out
        self.missing = missing
        self.duration = duration

    @property
    def ok(self) -> bool:
        """L'outil a produit une sortie exploitable (rc 0)."""
        return not self.missing and not self.timed_out and self.rc == 0

    @property
    def status(self) -> str:
        if self.missing:
            return "introuvable"
        if self.timed_out:
            return "timeout"
        return "ok" if self.rc == 0 else f"erreur (rc={self.rc})"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "cmd": " ".join(self.cmd),
            "rc": self.rc,
            "status": self.status,
            "timed_out": self.timed_out,
            "duration_sec": round(self.duration, 1),
        }


def make_tmp_dir(base: str = None) -> str:
    """Crée un répertoire temporaire par scan (logs bruts)."""
    root = base or os.path.join(tempfile.gettempdir(), "codescan-kali")
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    path = os.path.join(root, stamp)
    os.makedirs(path, exist_ok=True)
    return path


def run_one(tool_name: str, cmd: list, timeout=None, tmp_dir: str = None) -> ToolResult:
    """Exécute `cmd`, capture sa sortie brute.

    `timeout` : limite en secondes (mode normal), ou `None` pour **aucune
    limite de temps** (mode maximal d'IRON MAN AI — les outils tournent
    jusqu'à leur terme). Si `tmp_dir` est donné, la sortie brute est écrite
    dans `<tmp_dir>/<tool_name>.txt` (et `<tool_name>.err.txt` pour stderr).
    """
    import time
    started = time.monotonic()
    result = ToolResult(tool_name, cmd)

    if not cmd:
        result.missing = True
        return result

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        result.rc = proc.returncode
        result.stdout = proc.stdout or ""
        result.stderr = proc.stderr or ""
    except FileNotFoundError:
        result.missing = True
    except subprocess.TimeoutExpired as exc:
        result.timed_out = True
        result.stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        result.stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    except OSError as exc:  # e.g. permission refusée
        result.stderr = str(exc)
        result.rc = 1

    result.duration = time.monotonic() - started

    if tmp_dir:
        os.makedirs(tmp_dir, exist_ok=True)
        with open(os.path.join(tmp_dir, f"{tool_name}.txt"), "w",
                  encoding="utf-8", errors="replace") as fh:
            fh.write(result.stdout)
        if result.stderr:
            with open(os.path.join(tmp_dir, f"{tool_name}.err.txt"), "w",
                      encoding="utf-8", errors="replace") as fh:
                fh.write(result.stderr)
    return result


def dry_run_commands(tools: list, target: dict, tmp_dir: str,
                     wordlist: str = None) -> list:
    """Renvoie (sans exécuter) les commandes qui seraient lancées — dry-run.

    `tools` : liste (name, spec) issue de `tools.all_tools`.
    """
    lines = []
    for name, spec in tools:
        cmd = spec["cmd"](target, {"tmp": tmp_dir, "wordlist": wordlist or ""})
        display = " ".join(cmd) if cmd else "desactive (wordlists requises)"
        lines.append(f"{name:<10} -> {display}")
    return lines
"""Paquet `reports` de CodeScan : génération des rapports JSON et HTML.

Dossier central des rapports : `rapports/` à la racine du projet. Tous
les modules (CodeScan, audit web, WiFi, Android, périphérique) y écrivent
leurs rapports par défaut, avec un horodatage pour éviter tout écrasement.
"""

import os
import time

__version__ = "1.4.0"

# Nom du dossier central des rapports (racine du projet).
REPORT_DIR_NAME = "rapports"


def report_dir() -> str:
    """Chemin absolu du dossier central des rapports (créé si absent)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, REPORT_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def timestamped_path(prefix: str, ext: str = ".json") -> str:
    """Chemin d'un rapport horodaté : rapports/<prefix>_<AAAAMMJJ_HHMMSS><ext>."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(report_dir(), f"{prefix}_{ts}{ext}")

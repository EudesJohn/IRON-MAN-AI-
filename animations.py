#!/usr/bin/env python3
"""
IRON MAN AI - Animations de chargement
Spinners, barres de progression, phases de scan, messages motivants.
Compatible Windows (encodage securise).
"""

import sys
import os
import time
import threading
import random

# Fix Windows encoding - only wrap if not already wrapped
if sys.platform == 'win32':
    import io
    try:
        if hasattr(sys.stdout, 'buffer') and not isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'buffer') and not isinstance(sys.stderr, io.TextIOWrapper):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass
    os.system('')

# ─── Couleurs ──────────────────────────────────────────────────────────
R = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
MAGENTA = "\033[95m"


def _safe_write(text):
    """Ecriture securisee qui gere les erreurs d'encodage Windows."""
    try:
        if sys.stdout and not sys.stdout.closed:
            sys.stdout.write(text)
            sys.stdout.flush()
    except (UnicodeEncodeError, ValueError, OSError):
        try:
            if sys.stdout and not sys.stdout.closed:
                safe = text.encode('ascii', errors='replace').decode('ascii')
                sys.stdout.write(safe)
                sys.stdout.flush()
        except Exception:
            pass


# ─── Spinners (ASCII only pour compatibilite Windows) ─────────────────

SPINNERS = {
    "dots": ["", ".", "..", "...", "....", "...", "..", "."],
    "bar": ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]"],
    "arrows": ["< ", "^ ", "> ", "v "],
    "pulse": ["o", "O", "0", "O", "o"],
    "scan": ["-----", "=====", "-----", "====="],
    "rocket": ["*", "+", "x", "+"],
    "matrix": ["0", "1", "01", "10", "11", "001", "110", "101", "011", "000"],
}

# ─── Messages motivants (pendant le scan) ─────────────────────────────

SCANNING_MESSAGES = [
    "Analyse des ports ouverts...",
    "Detection des services...",
    "Verification des headers HTTP...",
    "Scan des vulnerabilites...",
    "Exploration des chemins web...",
    "Test des injections SQL...",
    "Detection des failles XSS...",
    "Analyse des certificats SSL...",
    "Reconnaissance DNS...",
    "Detection du WAF...",
    "Enumeration des sous-domaines...",
    "Analyse des reponses HTTP...",
    "Verification des en-tetes de securite...",
    "Test des permalinks...",
    "Scan des templates...",
]

TOOLS_MESSAGES = {
    "nmap": [
        "Nmap: Scan des ports et services...",
        "Nmap: Detection des versions...",
        "Nmap: Cartographie du reseau...",
    ],
    "whatweb": [
        "WhatWeb: Identification des technologies...",
        "WhatWeb: Analyse du serveur...",
        "WhatWeb: Detection des CMS...",
    ],
    "nuclei": [
        "Nuclei: Scan des templates de vulnerabilites...",
        "Nuclei: Verification des CVE...",
        "Nuclei: Test des failles connues...",
    ],
    "dirsearch": [
        "Dirsearch: Enumeration des repertoires...",
        "Dirsearch: Recherche de fichiers caches...",
        "Dirsearch: Exploration de l'arborescence...",
    ],
    "sqlmap": [
        "SQLMap: Test des injections SQL...",
        "SQLMap: Analyse des parametres...",
        "SQLMap: Detection des bases de donnees...",
    ],
    "wafw00f": [
        "WAFW00F: Detection du pare-feu applicatif...",
        "WAFW00F: Identification du WAF...",
    ],
    "dnsrecon": [
        "DNSRecon: Reconnaissance DNS...",
        "DNSRecon: Analyse des enregistrements...",
    ],
    "xsstrike": [
        "XSSStrike: Detection des failles XSS...",
        "XSSStrike: Test des injections de scripts...",
    ],
    "commix": [
        "Commix: Test des injections de commandes...",
        "Commix: Analyse des parametres d'execution...",
    ],
}

# ─── Messages de succes ────────────────────────────────────────────────

SUCCESS_MESSAGES = [
    "Scan termine avec succes !",
    "Analyse complete !",
    "Tous les outils ont ete executes !",
    "Mission accomplie !",
    "Rapport genere !",
]


class Spinner:
    """Spinner anime qui tourne en arriere-plan."""

    def __init__(self, message="Chargement", style="dots", color=CYAN):
        self.message = message
        self.style = style
        self.color = color
        self.frames = SPINNERS.get(style, SPINNERS["dots"])
        self.running = False
        self._thread = None
        self._interval = 0.15

    def _animate(self):
        i = 0
        while self.running:
            frame = self.frames[i % len(self.frames)]
            _safe_write(f"\r{self.color}  {frame} {self.message}{R}  ")
            time.sleep(self._interval)
            i += 1
        _safe_write(f"\r{self.color}  OK {self.message}{R}\n")

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self, success=True):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)


class ProgressBar:
    """Barre de progression animee."""

    def __init__(self, total=100, width=40, label="Progression", color=CYAN):
        self.total = total
        self.current = 0
        self.width = width
        self.label = label
        self.color = color

    def update(self, value=None, increment=1):
        if value is not None:
            self.current = value
        else:
            self.current += increment
        self.current = min(self.current, self.total)
        self._display()

    def _display(self):
        pct = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * pct)
        bar = "#" * filled + "-" * (self.width - filled)
        _safe_write(
            f"\r{self.color}  {self.label} [{bar}] {pct*100:.0f}%{R}"
        )

    def finish(self, message="Termine"):
        self.current = self.total
        self._display()
        _safe_write(f"\r{GREEN}  OK {message}{R}\n")


class ScanAnimator:
    """Gestionnaire d'animations pour un scan complet."""

    def __init__(self, target_url=None):
        self.target_url = target_url

    def show_tool_start(self, tool_name):
        """Affiche le demarrage d'un outil avec animation."""
        messages = TOOLS_MESSAGES.get(tool_name, [f"... {tool_name} en cours..."])
        msg = random.choice(messages)

        bar = ProgressBar(total=10, width=30, label=f"{tool_name:<10}", color=CYAN)
        for i in range(11):
            bar.update(value=i)
            time.sleep(0.05)
        bar.finish(message=msg)

    def show_tool_end(self, tool_name, success=True, duration=None):
        """Affiche la fin d'un outil."""
        if success:
            dur_str = f" ({duration:.1f}s)" if duration else ""
            _safe_write(f"{GREEN}  OK {tool_name} termine{dur_str}{R}\n")
        else:
            _safe_write(f"{YELLOW}  !! {tool_name} echoue ou indisponible{R}\n")

    def show_scan_progress(self, current_tool, total_tools, tool_name=""):
        """Affiche la progression globale du scan."""
        pct = (current_tool / total_tools * 100) if total_tools > 0 else 0
        filled = int(30 * current_tool / total_tools) if total_tools > 0 else 0
        bar = "#" * filled + "-" * (30 - filled)

        msg = random.choice(SCANNING_MESSAGES) if not tool_name else f"Outil: {tool_name}"

        _safe_write(
            f"\r{CYAN}  [{bar}] {current_tool}/{total_tools} - {msg}{R}  "
        )

    def show_scan_complete(self, tools_ok, tools_total, duration=None):
        """Affiche la fin du scan."""
        _safe_write(f"\n\n{BLUE}{'='*60}{R}\n")
        _safe_write(f"{GREEN}  SCAN TERMINE{R}\n")
        _safe_write(f"{BLUE}{'='*60}{R}\n")
        _safe_write(f"  Outils executes : {CYAN}{tools_ok}/{tools_total}{R}\n")
        if duration:
            _safe_write(f"  Duree totale    : {CYAN}{duration:.1f}s{R}\n")
        _safe_write(f"{BLUE}{'='*60}{R}\n\n")

    def show_phases(self):
        """Affiche les phases du scan avec animation."""
        phases = [
            ("Reconnaissance", "Analyse initiale de la cible"),
            ("Enumeration", "Decouverte des chemins et services"),
            ("Vulnerabilite", "Detection des failles potentielle"),
            ("Exploitation", "Test des failles detectees"),
            ("Rapport", "Generation du rapport final"),
        ]

        _safe_write(f"\n{CYAN}  Phases du scan :{R}\n\n")
        for i, (phase, desc) in enumerate(phases, 1):
            for j in range(3):
                dots = "." * (j + 1)
                _safe_write(f"\r{YELLOW}  [{i}/{len(phases)}] {phase:<20} {dots:<3}{R}")
                time.sleep(0.2)

            _safe_write(f"\r{GREEN}  [{i}/{len(phases)}] {phase:<20} OK{R}\n")
            time.sleep(0.1)

    def show_countdown(self, seconds=3, message="Demarrage dans"):
        """Affiche un compte a rebours."""
        for i in range(seconds, 0, -1):
            _safe_write(f"\r{YELLOW}  {message} {i}...{R}")
            time.sleep(1)
        _safe_write(f"\r{GREEN}  {message} GO !{R}\n")

    def show_random_tip(self):
        """Affiche un conseil aleatoire pendant le scan."""
        tips = [
            "Astuce : Les rapports HTML sont plus lisibles que les JSON",
            "Astuce : Utilisez --attack pour detecter les failles critiques",
            "Astuce : Les scans complets prennent 5-10 minutes",
            "Astuce : Verifiez les rapports dans le dossier rapports/",
            "Astuce : Utilisez --exploit pour tester automatiquement les failles",
            "Astuce : Les outils fonctionnent mieux sur Linux/Kali",
            "Astuce : Lancez en admin pour installer tous les outils",
        ]
        _safe_write(f"\n{DIM}{random.choice(tips)}{R}\n")


def show_loading_dots(message="Chargement", duration=2, color=CYAN):
    """Affiche des points de chargement pendant une duree donnee."""
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        dots = "." * ((i % 4))
        _safe_write(f"\r{color}  {message}{dots}   {R}")
        time.sleep(0.4)
        i += 1
    _safe_write(f"\r{GREEN}  {message} OK{R}\n")


def show_scan_intro(target, scan_type="complet"):
    """Affiche l'intro animee d'un scan."""
    anim = ScanAnimator(target)

    _safe_write(f"\n{BLUE}{'='*60}{R}\n")
    _safe_write(f"{YELLOW}  +------------------------------------+{R}\n")
    _safe_write(f"{YELLOW}  |       IRON MAN AI - SCAN           |{R}\n")
    _safe_write(f"{YELLOW}  |      Fait par Eudes Johnson        |{R}\n")
    _safe_write(f"{YELLOW}  +------------------------------------+{R}\n")
    _safe_write(f"{BLUE}{'='*60}{R}\n")

    _safe_write(f"\n{CYAN}  Cible   : {BOLD}{target}{R}\n")
    _safe_write(f"{CYAN}  Type    : {BOLD}{scan_type}{R}\n")
    _safe_write(f"{CYAN}  Date    : {BOLD}{time.strftime('%Y-%m-%d %H:%M:%S')}{R}\n")

    _safe_write(f"\n{BLUE}{'='*60}{R}\n")

    # Compte a rebours
    anim.show_countdown(3, "Demarrage du scan dans")


def show_tool_status(tools_status):
    """Affiche le statut de tous les outils avec animation."""
    _safe_write(f"\n{CYAN}  Statut des outils :{R}\n\n")

    for name, info in tools_status.items():
        if info.get("present"):
            icon = "[OK]"
            detail = "installe"
        elif info.get("alt_present"):
            icon = "[OK]"
            detail = f"via {info.get('alt_name', '?')}"
        else:
            icon = "[--]"
            detail = "manquant"

        _safe_write(f"    {icon} {name:<12} {DIM}{detail}{R}\n")
        time.sleep(0.05)


def show_report_generation():
    """Animee la generation du rapport."""
    _safe_write(f"\n{CYAN}  Generation du rapport...{R}\n\n")

    steps = [
        ("Collecte des resultats", 0.3),
        ("Analyse des donnees", 0.3),
        ("Formatage du rapport", 0.3),
        ("Creation du PDF/HTML", 0.3),
        ("Finalisation", 0.2),
    ]

    for i, (step, delay) in enumerate(steps, 1):
        for j in range(5):
            dots = "." * ((j % 4))
            _safe_write(f"\r{YELLOW}  [{i}/{len(steps)}] {step}{dots}   {R}")
            time.sleep(delay / 5)

        _safe_write(f"\r{GREEN}  [{i}/{len(steps)}] {step} OK{R}\n")
        time.sleep(0.1)

    _safe_write(f"\n{GREEN}  Rapport genere avec succes !{R}\n")

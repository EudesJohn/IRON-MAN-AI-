"""CodeScan — analyseur statique de code, sans aucune API d'IA.

Point d'entrée CLI (argparse) qui orchestre le pipeline complet :
  1. récupération de la cible (dossier local ou clone GitHub) ;
  2. exploration des fichiers (crawler) ;
  3. analyse AST Python, analyse générique regex, détection de secrets ;
  4. vérification des dépendances contre OSV.dev ;
  5. filtrage, statistiques et génération des rapports (JSON / HTML /
     résumé console).

Usage :
    python main.py --path ./mon_projet --output report.html
    python main.py --repo https://github.com/user/repo --output report.json \\
        --severity-min=medium --verbose
"""

import argparse
import json
import os
import sys
from datetime import datetime

from scanner import __version__
from scanner.crawler import cleanup_dir, clone_repo, read_text_file, walk_files
from scanner.dependency_checker import DependencyChecker
from scanner.generic_analyzer import GenericAnalyzer
from scanner.models import SEVERITIES, Finding, severity_ge
from scanner.python_analyzer import PythonAnalyzer
from scanner.quality_analyzer import QualityAnalyzer
from scanner.scorer import compute_score
from scanner.secrets_detector import SecretsDetector
from reports.html_report import write_html_report
from reports.json_report import write_json_report
from reports import timestamped_path

# Chemin par défaut de la base de patterns externalisés.
RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "rules", "patterns.json")

# Langages analysés par l'analyseur de qualité (métriques de fonction,
# lignes longues, async/perf JS…). Hors de cette liste, un fichier n'est
# pas analysé par QualityAnalyzer (pas de bruit sur config/yml/json).
QUALITY_LANGS = {
    "python", "javascript", "typescript", "php", "java", "csharp", "go",
    "kotlin", "scala", "rust", "swift", "c", "cpp", "ruby",
}


# ---------------------------------------------------------------------------
# Règles / utilitaires
# ---------------------------------------------------------------------------

def load_rules(path: str = None):
    """Charge les patterns génériques et secrets depuis rules/patterns.json."""
    path = path or RULES_PATH
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("generic", []), data.get("secrets", [])


def compute_stats(findings, files_scanned: int) -> dict:
    """Agrège les statistiques par sévérité et par catégorie."""
    by_severity = {s: 0 for s in SEVERITIES}
    by_category = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
    return {
        "total_findings": len(findings),
        "files_scanned": files_scanned,
        "by_severity": by_severity,
        "by_category": by_category,
    }


def dedupe(findings) -> list:
    """Supprime les doublons stricts (même fichier, ligne, règle, titre).

    On conserve le finding de sévérité la plus élevée.
    """
    seen = {}
    for f in findings:
        key = (f.file, f.line, f.rule_id, f.title)
        prev = seen.get(key)
        if prev is None or f.severity_rank > prev.severity_rank:
            seen[key] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Résumé console
# ---------------------------------------------------------------------------

# Codes ANSI pour la sortie console (désactivés si non-TTY).
def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


SEV_ANSI = {
    "critical": "1;31", "high": "1;33", "medium": "0;33", "low": "0;36",
}


def print_console_summary(stats, findings, target, verbose: bool,
                          score: dict = None) -> None:
    """Affiche le résumé de l'analyse dans le terminal.

    `score` (optionnel) est le dictionnaire renvoyé par compute_score()
    (clés : score, grade, total_findings…).
    """
    print()
    print(_color("1;36", "═" * 56))
    print(_color("1;36", "  CodeScan — Résumé de l'analyse"))
    print(_color("1;36", "═" * 56))
    print(f"  Cible              : {target}")
    print(f"  Fichiers analysés  : {stats['files_scanned']}")
    if score:
        grade = score.get("grade", "")
        print(f"  Score de qualité   : {score['score']}/100 "
              f"({_color('1;32', grade)})")
    elif score is not None:
        print("  Score de qualité   : désactivé (--no-score)")
    print(f"  Total findings     : {stats['total_findings']}")

    print()
    print("  Par sévérité :")
    by_sev = stats["by_severity"]
    for sev in SEVERITIES:
        n = by_sev.get(sev, 0)
        bar = "█" * min(n, 30) or "·"
        print(f"    {_color(SEV_ANSI[sev], f'{sev:8s}')} {n:<4d} {bar}")

    print()
    print("  Par catégorie :")
    for cat, n in sorted(stats["by_category"].items(), key=lambda kv: -kv[1]):
        print(f"    {cat:<18s} {n}")

    if verbose:
        print()
        print("  Détail (verbose) :")
        for f in sorted(findings, key=lambda x: (-x.severity_rank, x.file, x.line)):
            sev_lbl = _color(SEV_ANSI[f.severity], f.severity.ljust(8))
            print(f"    {sev_lbl} {f.file}:{f.line}  {f.rule_id}  {f.title[:60]}")

    print(_color("1;36", "═" * 56))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments de la CLI."""
    parser = argparse.ArgumentParser(
        prog="CodeScan",
        description=("Analyse statique de code (Python, JS, PHP, Java…) "
                     "sans aucune API d'IA — règles AST, regex et base de "
                     "vulnérabilités OSV.dev."),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    source = parser.add_argument_group("Cible")
    source.add_argument("--path", metavar="CHEMIN",
                        help="Dossier local du projet à analyser.")
    source.add_argument("--repo", metavar="URL",
                        help="URL GitHub à cloner puis analyser (ex. "
                             "https://github.com/user/repo).")

    parser.add_argument("-o", "--output", metavar="FICHIER",
                        help="Rapport de sortie (.json ou .html). "
                             "Sans cet argument, résumé console seul.")
    parser.add_argument("--severity-min", default="low",
                        choices=["critical", "high", "medium", "low"],
                        help="Sévérité minimale des résultats retenus.")
    parser.add_argument("--no-deps", action="store_true",
                        help="Désactive la vérification des CVE via OSV.dev.")
    parser.add_argument("--no-quality", action="store_true",
                        help="Désactive l'analyse de qualité de code "
                             "(métriques de fonction, async/perf JS…).")
    parser.add_argument("--no-score", action="store_true",
                        help="Ne calcule ni n'affiche la note /100.")
    parser.add_argument("--rules", metavar="FICHIER",
                        help="Base de patterns alternative (JSON).")
    parser.add_argument("--exclude", metavar="MOTIF", action="append",
                        default=None,
                        help="Exclure les fichiers dont le chemin relatif contient "
                             "MOTIF (répétable ou séparé par des virgules ; jokers "
                             "* et ? acceptés). Ex. --exclude tests,migrations "
                             "ou --exclude '*.min.js'.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Sortie détaillée (fichiers explorés, détail des findings).")
    parser.add_argument("--version", action="version",
                        version=f"CodeScan {__version__}")
    return parser


def main(argv=None) -> int:
    """Orchestre l'analyse complète. Renvoie le code de sortie."""
    # Encodage UTF-8 de la sortie console (Windows notamment).
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    args = build_parser().parse_args(argv)

    if not args.path and not args.repo:
        print("[ERREUR] Indiquez une cible : --path <dossier> ou --repo <URL>.",
              file=sys.stderr)
        return 2

    # --- 1. Récupération de la cible ------------------------------------
    temp_dir = None
    if args.repo:
        try:
            root = clone_repo(args.repo, verbose=args.verbose)
            temp_dir = root
        except RuntimeError as exc:
            print(f"[ERREUR] {exc}", file=sys.stderr)
            return 1
    else:
        root = os.path.abspath(args.path)
        if not os.path.isdir(root):
            print(f"[ERREUR] Le dossier {root} n'existe pas.", file=sys.stderr)
            return 1

    try:
        return _run_analysis(root, temp_dir, args)
    finally:
        cleanup_dir(temp_dir)


def _flatten_excludes(patterns) -> list:
    """Aplatie la liste --exclude (chaque entrée peut être comma-séparée)."""
    out = []
    for pat in patterns or []:
        for p in pat.split(","):
            p = p.strip()
            if p:
                out.append(p)
    return out


def _is_excluded(relpath: str, patterns: list) -> bool:
    """True si le chemin relatif correspond à un motif d'exclusion.

    Trois règles : sous-chaîne exacte du chemin, joker sur le chemin
    complet (fnmatch), joker sur le nom de fichier seul.
    """
    import fnmatch
    base = os.path.basename(relpath)
    for pat in patterns:
        if pat in relpath:
            return True
        if fnmatch.fnmatch(relpath, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


def _run_analysis(root: str, temp_dir: str, args) -> int:
    """Pipeline d'analyse proprement dit (exécuté entre les étapes CLI)."""
    # --- 2. Règles + analyseurs -----------------------------------------
    try:
        generic_patterns, secret_patterns = load_rules(args.rules)
    except OSError as exc:
        print(f"[ERREUR] Impossible de charger les règles : {exc}",
              file=sys.stderr)
        return 1

    python_analyzer = PythonAnalyzer(verbose=args.verbose)
    generic_analyzer = GenericAnalyzer(generic_patterns, verbose=args.verbose)
    secrets_detector = SecretsDetector(secret_patterns, verbose=args.verbose)
    quality_analyzer = QualityAnalyzer(verbose=args.verbose)
    dep_checker = DependencyChecker(offline=args.no_deps, verbose=args.verbose)

    # --- 3. Exploration ---------------------------------------------------
    files = walk_files(root, verbose=args.verbose)
    if args.exclude:
        patterns = _flatten_excludes(args.exclude)
        kept = [sf for sf in files if not _is_excluded(sf.relpath, patterns)]
        if args.verbose:
            print(f"[main] --exclude : {len(files) - len(kept)} fichier(s) exclu(s)")
        files = kept
    if args.verbose:
        print(f"[main] {len(files)} fichiers retenus pour l'analyse")

    # --- 4. Analyse -------------------------------------------------------
    all_findings = []
    manifest_files = []

    for sf in files:
        content = read_text_file(sf.path)

        # Analyse AST spécifique à Python
        if sf.kind == "python":
            all_findings.extend(python_analyzer.analyze(sf, content))

        # Analyse générique regex (tous les fichiers source/config)
        if sf.kind in ("python", "source", "config"):
            all_findings.extend(generic_analyzer.analyze(sf, content))

        # Analyse de qualité (métriques de fonction, lignes longues,
        # async/perf JS…) sur les langages supportés.
        if not args.no_quality and sf.language in QUALITY_LANGS:
            all_findings.extend(quality_analyzer.analyze(sf, content))

        # Détection de secrets (contenu brut)
        if sf.kind in ("python", "source", "config"):
            all_findings.extend(secrets_detector.detect(sf, content))

        # Manifestes de dépendances (analysés après)
        if sf.kind == "manifest":
            manifest_files.append(sf)

    # --- 5. Dépendances (OSV.dev) -----------------------------------------
    if manifest_files:
        all_findings.extend(dep_checker.analyze(manifest_files))

    # --- 6. Dédup + score + filtrage + tri --------------------------------
    # On déduplique d'abord, puis on calcule le score sur l'ensemble
    # dédupliqué complet : la note reflète l'état réel du projet, sans
    # dépendre du filtre --severity-min (qui ne sert qu'à l'affichage).
    deduped = dedupe(all_findings)
    score = None if args.no_score else compute_score(deduped, len(files))

    findings = [
        f for f in deduped if severity_ge(f.severity, args.severity_min)
    ]
    findings.sort(key=lambda f: (-f.severity_rank, f.file, f.line))

    stats = compute_stats(findings, len(files))
    print_console_summary(stats, findings, root, args.verbose, score)

    # --- 7. Rapport --------------------------------------------------------
    # Sans --output : les rapports JSON + HTML sont écrits par défaut dans
    # le dossier central `rapports/` (horodatés, jamais écrasés).
    defaulted = args.output is None
    if defaulted:
        args.output = timestamped_path("codescan", ".json")
    ext = os.path.splitext(args.output)[1].lower()
    meta = {
        "tool": "CodeScan",
        "version": __version__,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": root,
        "severity_min": args.severity_min,
    }
    try:
        if ext == ".json":
            write_json_report(findings, root, stats, args.output, meta,
                              score=score)
            if defaulted:
                html = os.path.splitext(args.output)[0] + ".html"
                write_html_report(findings, stats, root, meta, html,
                                  score=score)
                print(f"[main] Rapports écrits : {args.output} / {html}")
            else:
                print(f"[main] Rapport JSON écrit : {args.output}")
        elif ext == ".html":
            write_html_report(findings, stats, root, meta, args.output,
                              score=score)
            print(f"[main] Rapport HTML écrit : {args.output}")
        else:
            print("[main] Format non reconnu pour --output "
                  "(utilisez .json ou .html).", file=sys.stderr)
            return 2
    except OSError as exc:
        print(f"[ERREUR] Écriture du rapport impossible : {exc}",
              file=sys.stderr)
        return 1

    # Code de sortie : 1 si des failles critiques/haute ont été trouvées
    # (utile pour du CI), 0 sinon.
    severe = [f for f in findings if f.severity in ("critical", "high")]
    return 1 if severe else 0


if __name__ == "__main__":
    sys.exit(main())

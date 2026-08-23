"""IRON MAN AI — Audit Kali : audit de sécurité d'un site web.

Avec `--check`, vérifie que les outils Kali requis sont présents et
affiche la commande d'installation des paquets manquants ; sinon lance un
audit complet de la cible avec tous les outils disponibles (nmap, nikto,
whatweb, gobuster, dirsearch, sslscan, nuclei, wafw00f, dnsrecon) puis,
avec `--attack`, les outils invasifs (sqlmap, xsstrike, commix, hydra).

Le drapeau **--full** (alias : la commande unique `ironman.py`) lance
**tout** : outils invasifs compris, sans limite de temps, au maximum
(scan nmap `-p- -sC`, wordlist complète, threads élevés) et produit
l'audit complet en JSON, HTML **et PDF**.

Exemples :
    python kali_scan.py --check --attack
    python kali_scan.py --url http://example.com --authorized --check
    python kali_scan.py --url http://example.com --authorized --attack \\
        --output rapport.html
    python kali_scan.py --url http://127.0.0.1:8000 --authorized --dry-run
    python ironman.py --url http://127.0.0.1:8000 --authorized
"""

import argparse
import os
import sys

from kali import __version__
from kali.pdf import write_web_pdf
from kali.preflight import (
    check_tools, install_commands, missing_tools, print_preflight,
)
from kali.report import build_meta, write_web_report
from kali.runner import make_tmp_dir, run_one
from kali.tools import all_tools, applies
from kali.urls import split_target
from kali.parsers import parse_output
from kali.auto_exploit import auto_exploit, exploit_results_to_findings, generate_exploit_report
from reports import timestamped_path
from kali.wordlist import wordlist_path
from scanner.models import severity_ge
from scanner.scorer import compute_score


def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _banner(text: str) -> str:
    return _color("1;31", "═" * 62) + "\n" + text + "\n" + _color("1;31", "═" * 62)


def _ironman_banner(full: bool = False) -> str:
    """Bannière de marque IRON MAN AI."""
    if full:
        mode = _color("1;33", "IRON MAN AI — mode maximal : tous les outils, "
                              "aucune limite de temps")
    else:
        mode = _color("1;36", "IRON MAN AI — outils web (mode normal)")
    return (
        _color("1;31", "╦═╗ ╦ ╦ ╔═╗ ╦   ")
        + _color("1;33", "╔╦╗╔═╗╔╗╔╦╔═╗╦═╗")
        + "\n"
        + _color("1;31", "╠═╝ ╚╦╝ ╠╣ ║   ")
        + _color("1;33", " ║║║║║║║║║║║║╔═╝")
        + "\n"
        + _color("1;31", "╩    ╩  ╚═╝╩═╝")
        + _color("1;33", "═╩╝╚╩═╝╚╝╚╩╚═╝╩")
        + "\n"
        + mode
    )


def print_scan_summary(findings, by_tool, target_url, score) -> None:
    """Résumé console du scan web."""
    print()
    print(_color("1;36", "═" * 62))
    print(_color("1;36", "  IRON MAN AI — Audit Kali : résumé"))
    print(_color("1;36", "═" * 62))
    print(f"  Cible          : {target_url}")
    print(f"  Outils lancés  : {len(by_tool)}")
    if score:
        print(f"  Score web      : {score['score']}/100 "
              f"({_color('1;32', score.get('grade', ''))})")
    print(f"  Total findings : {len(findings)}")
    print()
    print("  Par outil :")
    for name, info in by_tool.items():
        status = info.get("status", "?")
        n = info.get("count", 0)
        bar = "█" * min(n, 30) or "·"
        print(f"    {name:<10} {status:<14} {n:<4d} {bar}")
    if findings:
        print()
        print("  Détail (outil · règle — les plus graves d'abord) :")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(findings, key=lambda x: (order.get(x.severity, 4),
                                                 x.source, x.rule_id)):
            sev_color = "1;31" if f.severity == "critical" else (
                "1;33" if f.severity == "high" else "0;36")
            print(f"    {_color(sev_color, f.severity.ljust(8))} "
                  f"{f.source:<10} {f.rule_id:<30} {f.title[:56]}")
    print(_color("1;36", "═" * 62))


def _output_paths(params: str, want_pdf: bool) -> list:
    """Chemins des rapports à écrire : (fichier, extension).

    - avec `--output rapport.html` : rapport.html, et si `--pdf`, rapport.pdf ;
    - sans `--output` : rien, sauf `--pdf` (audit complet) : rapports
      JSON, HTML et PDF écrits par défaut dans le dossier central
      `rapports/` (horodatés).
    """
    exts = []
    if params:
        exts.append(os.path.splitext(params)[1].lower() or ".json")
    elif want_pdf:
        exts = [".json", ".html"]
    if want_pdf and ".pdf" not in exts:
        exts.append(".pdf")
    if not exts:
        return []
    if params:
        base = os.path.splitext(params)[0]
    else:
        base = os.path.splitext(timestamped_path("audit_web", ".json"))[0]
    return [(base + ext, ext) for ext in exts]


def _scan(args) -> int:
    """Orchestre le scan IRON MAN et renvoie le code de sortie."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    # --- Sécurité : cible autorisée ? ---------------------------------------
    if not args.check and not args.authorized:
        print("[ERREUR] --authorized est obligatoire pour scanner (confirmation "
              "que vous êtes autorisé à tester cette cible).", file=sys.stderr)
        return 2

    # --- Préflight : présence des outils -----------------------------------
    attack = args.attack or args.full
    status = check_tools(attack=attack)
    print_preflight(status, verbose=args.verbose)

    missing_web = [n for n, info in missing_tools(status) if info["tier"] == "web"]
    if missing_web and not args.check:
        print(_banner(
            "[Préflight] Des outils « web » manquent. Commande(s) à exécuter :"))
        for cmd in install_commands(missing_tools(status)):
            print("  " + cmd)
        if not args.allow_missing and not args.dry_run:
            print(_banner("[Préflight] Scan annulé : installez d'abord les outils "
                          "(ou ajoutez --allow-missing pour continuer sans eux)."))
            return 2

    if args.check:
        print("[IRON MAN AI] Vérification terminée — aucun scan lancé.")
        return 1 if missing_web else 0

    if not args.authorized:
        return 2

    if not args.url:
        print("[ERREUR] Indiquez une cible : --url <URL>.", file=sys.stderr)
        return 2
    target = split_target(args.url)
    if not target["host"]:
        print(f"[ERREUR] URL invalide : {args.url}", file=sys.stderr)
        return 2

    print(_ironman_banner(full=args.full))

    tmp_dir = make_tmp_dir()
    # Mode maximal : wordlist complète (aucune limite de requêtes).
    max_words = None if args.full else 200
    wordlist = wordlist_path(tmp_dir=tmp_dir, max_words=max_words)

    tools = all_tools(attack=attack)
    if args.tools:
        keep = {x.strip() for x in args.tools.split(",") if x.strip()}
        tools = [(n, s) for n, s in tools if n in keep]
    if args.exclude:
        drop = {x.strip() for x in args.exclude.split(",") if x.strip()}
        tools = [(n, s) for n, s in tools if n not in drop]

    ctx = {
        "tmp": tmp_dir,
        "wordlist": wordlist,
        "maximal": args.full,
        "hydra_users": args.hydra_users,
        "hydra_passwords": args.hydra_passwords,
    }

    # --- Dry-run : aucune commande lancée -----------------------------------
    if args.dry_run:
        print("[IRON MAN AI] Mode simulation (--dry-run) : aucune commande "
              "exécutée.")
        print(f"[IRON MAN AI] Wordlist : {wordlist}")
        print("[IRON MAN AI] Commandes prévues :")
        for name, spec in tools:
            if not applies(spec, target):
                print(f"  - {name:<10} non applicable à cette cible")
                continue
            cmd = spec["cmd"](target, dict(ctx))
            if not cmd:
                print(f"  - {name:<10} désactivé par défaut (wordlists requises)")
                continue
            print(f"  - {name:<10} -> {' '.join(cmd)}")
        return 0

    # --- Scan réel ----------------------------------------------------------
    findings = []
    by_tool = {}
    for name, spec in tools:
        if not applies(spec, target):
            by_tool[name] = {"ok": False, "status": "non applicable",
                             "duration_sec": 0.0, "count": 0}
            continue
        if not status[name]["present"]:
            by_tool[name] = {"ok": False, "status": "manquant",
                             "duration_sec": 0.0, "count": 0}
            continue
        cmd = spec["cmd"](target, dict(ctx))
        if not cmd:
            by_tool[name] = {"ok": False, "status": "désactivé (wordlists)",
                             "duration_sec": 0.0, "count": 0}
            continue
        print(f"[IRON MAN] {name}: {' '.join(cmd)}")
        # Mode maximal : aucun timeout par défaut (les outils tournent jusqu'à
        # leur terme), SAUF si --tool-timeout impose une limite raisonnable.
        if args.tool_timeout is not None:
            timeout = args.tool_timeout
        else:
            timeout = None if args.full else spec.get("timeout", 300)
        result = run_one(name, cmd, timeout, tmp_dir=tmp_dir)
        parsed = parse_output(name, result.stdout, target)
        findings.extend(parsed)
        by_tool[name] = {
            "ok": result.ok,
            "status": result.status,
            "duration_sec": round(result.duration, 1),
            "count": len(parsed),
        }

    score = compute_score(findings, len(by_tool) or 1)
    print_scan_summary(findings, by_tool, target["url"], score)

    # --- Exploitation automatique (--exploit) -------------------------------
    exploit_findings = []
    exploit_results = []
    if getattr(args, 'exploit', False) and findings:
        print()
        print(_color("1;31", "═" * 62))
        print(_color("1;31", "  IRON MAN AI — EXPLOITATION AUTOMATIQUE"))
        print(_color("1;31", "═" * 62))
        # Vérifier et installer les outils manquants
        from kali.auto_exploit import ensure_tools
        print("  [PRÉFLIGHT] Vérification des outils d'exploitation...")
        tool_status = ensure_tools()
        missing = [n for n, p in tool_status.items() if not p]
        if missing:
            print(_color("1;33", f"  ⚠️  Outils manquants : {', '.join(missing)}"))
            print("  Tentative d'installation via apt...")
            ensure_tools(missing)
        exploit_results = auto_exploit(findings, target, tmp_dir,
                                       timeout_per_tool=180)
        exploit_findings = exploit_results_to_findings(exploit_results)
        findings.extend(exploit_findings)
        # Re-calculer le score avec les findings d'exploitation
        score = compute_score(findings, len(by_tool) or 1)
        # Résumé exploitation
        proven = [r for r in exploit_results if r.success]
        tested = [r for r in exploit_results if not r.success]
        print()
        print(f"  Résultat exploitation : {len(proven)} prouvées / "
              f"{len(tested)} non exploitable / {len(exploit_results)} total")
        if proven:
            print(_color("1;31", "  ⚠️  FAILLES EXPLOITÉES :"))
            for r in proven:
                print(f"    🔴 {r.tool}: {r.proof}")
        # Générer le rapport d'exploitation
        try:
            from reports import report_dir
            exploit_dir = report_dir()
            report_path = generate_exploit_report(exploit_results, target["url"], exploit_dir)
            print(f"\n  📄 Rapport d'exploitation : {report_path}")
        except Exception as exc:
            print(f"\n  [INFO] Rapport d'exploitation non généré : {exc}")
        print(_color("1;31", "═" * 62))

    # --- Rapports (JSON / HTML / PDF) ---------------------------------------
    outputs = _output_paths(args.output, args.pdf)
    for path, ext in outputs:
        try:
            if ext == ".pdf":
                meta = build_meta(target["url"], attack, __version__)
                write_web_pdf(findings, by_tool, target["url"], meta, status,
                              path, score=score)
            else:
                write_web_report(findings, by_tool, target["url"], attack,
                                 status, path, __version__, score=score)
            print(f"[IRON MAN] Rapport écrit : {path}")
        except (OSError, ValueError) as exc:
            print(f"[ERREUR] Écriture du rapport impossible : {exc}",
                  file=sys.stderr)
            return 1

    # Code de sortie : 1 si des failles critique/haute ont été trouvées.
    severe = [f for f in findings if severity_ge(f.severity, "high")]
    return 1 if severe else 0


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur CLI (réutilisé par `ironman.py`)."""
    parser = argparse.ArgumentParser(
        prog="IRON MAN AI",
        description="Audit de sécurité d'un site web (outils Kali, stdlib).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", metavar="URL",
                        help="URL cible à scanner (http/https).")
    parser.add_argument("--check", "--preflight", action="store_true",
                        help="Vérifie la présence des outils, sans scanner.")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirme que vous êtes autorisé à tester la "
                             "cible (obligatoire pour un scan).")
    parser.add_argument("--attack", action="store_true",
                        help="Inclut les outils invasifs (sqlmap, xsstrike, "
                             "commix, hydra) — cibles autorisées uniquement.")
    parser.add_argument("--full", "--maximal", action="store_true",
                        help="Mode maximal : tous les outils (web + attack), "
                             "aucune limite de temps, wordlist complète, "
                             "nmap -p- -sC, et audit complet (JSON + HTML + PDF).")
    parser.add_argument("--pdf", action="store_true",
                        help="Produit aussi le rapport PDF de l'audit complet.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Affiche les commandes sans les exécuter "
                             "(aucun trafic réseau).")
    parser.add_argument("--tools", metavar="LISTE",
                        help="Limiter aux outils listés (ex : nmap,nuclei).")
    parser.add_argument("--exclude", metavar="LISTE",
                        help="Exclure des outils (ex : gobuster,dirsearch).")
    parser.add_argument("--hydra-users", metavar="FICHIER",
                        help="Wordlist d'identifiants pour hydra (requise "
                             "pour activer hydra en mode --attack).")
    parser.add_argument("--hydra-passwords", metavar="FICHIER",
                        help="Wordlist de mots de passe pour hydra (requise "
                             "pour activer hydra en mode --attack).")
    parser.add_argument("--allow-missing", action="store_true",
                        help="Lance le scan même si des outils web manquent.")
    parser.add_argument("--tool-timeout", metavar="SECONDES", type=int,
                        default=None,
                        help="Limite de temps par outil (secondes). En mode "
                             "maximal (--full), les outils tournent sans limite "
                             "par défaut : ce cap impose une borne raisonnable "
                             "à chacun (ex. --tool-timeout 600 = 10 min/outil).")
    parser.add_argument("-o", "--output", metavar="FICHIER",
                        help="Rapport web de sortie (.json ou .html).")
    parser.add_argument("--exploit", action="store_true",
                        help="Exploite automatiquement les failles trouvées : "
                             "dump BDD, brute-force 100+ credentials, "
                             "extraction de données sensibles. "
                             "--authorized obligatoire.")
    parser.add_argument("--dump", action="store_true",
                        help="Mode extraction complète : dump TOUTES les tables "
                             "de la BDD (sqlmap --dump-all), génère un PDF "
                             "avec les données extraites. "
                             "--exploit --authorized obligatoire.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Détail du préflight (raison de chaque outil).")
    parser.add_argument("--version", action="version",
                        version=f"IRON MAN AI {__version__}")
    # Défauts « max » : la commande unique ironman.py les garde ; kali_scan.py
    # les re-couvre en mode « normal » dans main().
    parser.set_defaults(full=True, pdf=True, attack=True)
    return parser


def main(argv=None) -> int:
    """Point d'entrée CLI de kali_scan.py (mode normal par défaut)."""
    parser = build_parser()
    parser.set_defaults(full=False, pdf=False, attack=False)
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    return _scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
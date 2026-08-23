"""IRON MAN AI — LA commande unique sur Kali.

Une seule commande pour tout faire :

    python ironman.py --url <URL> --authorized

Elle enchaîne **tous les outils** (web + attack) **l'un après l'autre**,
au **maximum**, **sans limite de temps d'analyse**, et produit **l'audit
complet en PDF** (avec le JSON et le HTML) : rien à paramétrer.

Équivaut à :
    python kali_scan.py --url <URL> --authorized --full --attack --pdf

Vous pouvez toujours surcharger : --check (préflight seul), --dry-run
(afficher les commandes), --tools/--exclude, --output (nom des rapports).
"""

import sys

from kali_scan import build_parser, _scan


def main(argv=None) -> int:
    """Point d'entrée : mêmes options que kali_scan.py, mais tout est FORCÉ
    au maximum par défaut (--full, --attack, --pdf)."""
    parser = build_parser()   # défauts déjà : full=True, attack=True, pdf=True
    args = parser.parse_args(argv)
    return _scan(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[IRON MAN AI] Audit interrompu par l'utilisateur.",
              flush=True)
        raise SystemExit(130)
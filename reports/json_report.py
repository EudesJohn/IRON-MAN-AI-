"""Rapport JSON structuré de CodeScan.

Produit un fichier JSON lisible par des outils tiers ou un pipeline CI :
métadonnées, statistiques agrégées et liste complète des findings.
"""

import json


def write_json_report(findings, target, stats, output_path, meta: dict,
                      score: dict = None) -> None:
    """Écrit le rapport JSON sur `output_path`.

    `score` (optionnel) : dictionnaire renvoyé par compute_score() ; il est
    sérialisé sous la clé top-level "score" s'il est fourni (absent avec
    `--no-score`).
    """
    report = {
        "meta": meta,
        "target": target,
        "summary": stats,
        "findings": [f.to_dict() for f in findings],
    }
    # La clé "score" n'est écrite que si une note a été calculée :
    # avec --no-score, elle est absente (pas de null dans le JSON).
    if score is not None:
        report["score"] = score
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

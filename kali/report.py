"""Rapports du mode WebScan Kali (JSON + HTML).

Réutilise les conventions du rapport statique (scanner.models.Finding,
scorer.compute_score, reports.json_report) et produit un HTML dédié aux
résultats web : cartes de synthèse, score, résultat par outil (statut,
durée), findings groupés par outil et table de préflight.
"""

from datetime import datetime

from scanner.models import SEVERITIES, level_for, severity_ge
from scanner.scorer import compute_score

try:
    from reports.html_webreport import generate_web_html, write_web_html
except ImportError:  # pragma: no cover - chute de secours si module absent
    generate_web_html = None
    write_web_html = None
from reports.json_report import write_json_report


def web_stats(findings, by_tool: dict) -> dict:
    """Statistiques agrégées du scan web (mêmes clés que le mode statique)."""
    by_severity = {s: 0 for s in SEVERITIES}
    by_category = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
    return {
        "total_findings": len(findings),
        "files_scanned": max(len(by_tool), 1),
        "by_severity": by_severity,
        "by_category": by_category,
    }


def build_meta(target_url: str, attack: bool, version: str) -> dict:
    """Métadonnées du rapport web."""
    return {
        "tool": "IRON MAN AI",
        "version": version,
        "mode": "web",
        "attack": attack,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target_url,
        "severity_min": "low",
    }


def write_web_report(findings, by_tool: dict, target_url: str, attack: bool,
                     preflight: dict, output_path: str, version: str,
                     score: dict = None) -> None:
    """Écrit le rapport web (.json ou .html selon l'extension)."""
    stats = web_stats(findings, by_tool)
    meta = build_meta(target_url, attack, version)
    if score is None:
        score = compute_score(findings, stats["files_scanned"])
    ext = output_path.lower()
    if ext.endswith(".json"):
        write_json_report(findings, target_url, stats, output_path, meta,
                          score=score)
    elif ext.endswith(".html"):
        if write_web_html is None:  # pragma: no cover
            raise ImportError("reports.html_webreport indisponible")
        write_web_html(findings, stats, by_tool, target_url, meta, preflight,
                       output_path, score)
    else:
        raise ValueError("Format de rapport non supporté (utilisez .json ou .html)")
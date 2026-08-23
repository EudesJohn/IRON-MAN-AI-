"""Calcul du score de qualité /100 et des statistiques par domaine.

Le score mesure la « dette » globale d'un projet : plus il y a de résultats
(pondérés par sévérité) et plus ils sont graves (critiques notamment),
plus le score baisse. Il est normalisé par le nombre de fichiers analysés
pour être comparable entre projets de tailles différentes.

Calibration : sur un projet type (78 fichiers, 1 critique, 400 haute,
430 moyenne, 19 basse) le score vaut ≈ 49/100 (note « D » — parité avec le
rapport Herald de référence).
"""

from scanner.models import SEVERITY_RANK, level_for
from scanner.thresholds import domain_of, grade_for

# Poids de chaque sévérité dans le score pondéré.
WEIGHTS = {"critical": 5, "high": 2, "medium": 1, "low": 0.5}

# Constante de normalisation du score (plus elle est grande, moins le
# score baisse vite avec la densité de findings).
SCORE_K = 15.5

# Facteur de pénalisation d'un finding critique (multiplié par la
# proportion de critiques par fichier).
CRIT_PENALTY = 0.5


def compute_score(findings, files_scanned: int) -> dict:
    """Calcule le score /100 d'un ensemble de findings dé-dupliqués.

    Arguments :
        findings     — liste de `Finding` (déjà dédupliqués si possible).
        files_scanned — nombre de fichiers explorés (dénominateur).

    Renvoie un dictionnaire prêt à sérialiser :
      {score, grade, total_findings, files_scanned,
       security, quality, performance,
       by_level, by_domain_pct, weights}
    """
    n_files = max(files_scanned or 0, 1)

    # Compteurs par sévérité, par domaine et par niveau lisible.
    by_severity = {sev: 0 for sev in SEVERITY_RANK}
    by_domain = {"security": 0, "quality": 0, "performance": 0}
    by_level = {lv: 0 for lv in ("CRITIQUE", "À REVOIR", "MINEUR")}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_domain[domain_of(f.category)] += 1
        by_level[level_for(f.severity)] += 1

    weighted = sum(
        by_severity.get(sev, 0) * WEIGHTS.get(sev, 0) for sev in SEVERITY_RANK
    )
    density = weighted / n_files
    crit_ratio = by_severity.get("critical", 0) / n_files

    # Formule :
    #   raw = 100 / (1 + density / K) * (1 - CRIT_PENALTY · crit_ratio)
    raw = 100.0 / (1.0 + density / SCORE_K) * (1.0 - CRIT_PENALTY * crit_ratio)
    score = max(0, min(100, round(raw)))

    total = len(findings)
    by_domain_pct = {
        dom: round(100 * count / total, 1) if total else 0.0
        for dom, count in by_domain.items()
    }

    return {
        "score": score,
        "grade": grade_for(score),
        "total_findings": total,
        "files_scanned": files_scanned or 0,
        "security": by_domain["security"],
        "quality": by_domain["quality"],
        "performance": by_domain["performance"],
        "by_level": by_level,
        "by_domain_pct": by_domain_pct,
        "weights": WEIGHTS,
    }
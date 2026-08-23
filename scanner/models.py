"""Modèle de données central de CodeScan.

Définit la structure d'un résultat d'analyse (Finding) ainsi que les
constantes partagées par tous les modules : sévérités et catégories.
"""

from dataclasses import dataclass, asdict

# Ordre de sévérité (du plus grave au moins grave), utilisé pour le tri
# des résultats et pour le filtrage --severity-min.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITIES = ["critical", "high", "medium", "low"]

# Niveaux « lisibles » du rapport (parité Herald) : les 4 sévérités sont
# regroupées en 3 niveaux français affichés dans le rapport.
LEVEL_BY_SEVERITY = {
    "critical": "CRITIQUE",
    "high": "À REVOIR",
    "medium": "À REVOIR",
    "low": "MINEUR",
}
LEVEL_ORDER = ["CRITIQUE", "À REVOIR", "MINEUR"]


def level_for(severity: str) -> str:
    """Niveau lisible (CRITIQUE / À REVOIR / MINEUR) d'une sévérité."""
    return LEVEL_BY_SEVERITY.get(severity, "À REVOIR")


@dataclass
class Finding:
    """Un résultat de l'analyse statique (une vulnérabilité suspectée)."""

    file: str                 # chemin relatif du fichier analysé
    line: int                 # numéro de ligne (0 si non applicable)
    column: int = 0           # colonne (optionnelle)
    rule_id: str = ""         # identifiant de la règle déclenchée
    category: str = "security_misc"
    severity: str = "medium"
    title: str = ""
    description: str = ""
    recommendation: str = ""
    snippet: str = ""         # extrait du code concerné
    language: str = ""        # langage du fichier
    cve: str = ""             # référence CVE (findings de dépendances)
    source: str = ""          # nom de l'analyseur émetteur
    exploitation: str = ""     # comment un attaquant exploite la faille
    attack_vector: str = ""    # vecteur d'attaque (network, local, adjacent)
    impact: str = ""           # impact concret si exploité (RCE, data leak…)
    admin_panel: str = ""      # URL du panneau admin découvert (si applicable)

    def to_dict(self) -> dict:
        """Convertit le finding en dictionnaire sérialisable JSON."""
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        """Niveau numérique de la sévérité (4 = critical … 1 = low)."""
        return SEVERITY_RANK.get(self.severity, 0)


def severity_ge(severity: str, minimum: str) -> bool:
    """Renvoie True si `severity` est au moins aussi grave que `minimum`."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 0)

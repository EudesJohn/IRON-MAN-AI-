"""Seuils de qualité, barême de lettres et domaines de résultats CodeScan.

Constantes centralisées consommées par l'analyseur de qualité, l'analyseur
Python (AST), le module de score et les rapports. Les valeurs reproduisent
celles observées dans le rapport Herald (parité de résultats) :
fonction > 50 lignes, cyclomatique > 10, cognitive > 15, imbrication > 4,
plus de 4 paramètres, lignes > 120 caractères, fichiers > 500 lignes.
"""

# ---------------------------------------------------------------------------
# Seuils des métriques de qualité
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "function_lines": 50,          # "Fonction trop longue : 79 lignes (max 50)"
    "cyclomatic_complexity": 10,   # "Complexité cyclomatique élevée : 20 (max 10)"
    "cognitive_complexity": 15,    # "Complexité cognitive élevée : 28 (max 15)"
    "nesting_depth": 4,            # "Imbrication excessive : 5 niveaux (max 4)"
    "max_params": 4,               # "Trop de paramètres : 5 (max 4)"
    "line_length": 120,            # "Ligne trop longue : 164 caractères (max 120)"
    "file_lines": 500,             # "Fichier trop long : 828 lignes (max 500)"
}


def threshold(key: str) -> int:
    """Renvoie le seuil correspondant à `key` (défaut : 0 si inconnu)."""
    return THRESHOLDS.get(key, 0)


# ---------------------------------------------------------------------------
# Barème de lettres (score /100 → A … F)
# ---------------------------------------------------------------------------

# Bande (score_minimum, lettre). 5 crans : reproduit l'exemple Herald
# « 49/100 D » (un score de 49 appartient à la bande D ≥ 40). Pour passer à
# une grille 6 crans (A≥90, B≥80, C≥70, D≥60, E≥40, F<40), modifier les
# bornes : la constante est centralisée ici.
GRADE_BANDS = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (40, "D"),
    (0, "F"),
)


def grade_for(score: int) -> str:
    """Lettre correspondant à `score` (0-100) selon GRADE_BANDS."""
    for minimum, grade in GRADE_BANDS:
        if score >= minimum:
            return grade
    return "F"


# ---------------------------------------------------------------------------
# Domaines du rapport (Sécurité / Qualité / Performance)
# ---------------------------------------------------------------------------

# Catégories dont les findings relèvent de la sécurité.
SECURITY_CATEGORIES = {
    "injection", "xss", "security_misc", "secrets", "dependencies",
}
# Catégories relevant de la qualité de code.
QUALITY_CATEGORIES = {"code_quality"}
# Catégories relevant de la performance / asynchronisme.
PERFORMANCE_CATEGORIES = {"performance"}


def domain_of(category: str) -> str:
    """Domaine d'une catégorie : security | quality | performance."""
    if category in SECURITY_CATEGORIES:
        return "security"
    if category in QUALITY_CATEGORIES:
        return "quality"
    if category in PERFORMANCE_CATEGORIES:
        return "performance"
    return "security"  # défaut (catégories inconnues → sécurité par prudence)
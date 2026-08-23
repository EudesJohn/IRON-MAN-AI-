"""Tests du rapport HTML enrichi (parité de structure Herald).

Vérifie la présence du hero score (/100 + lettre colorée + barre), des
cartes de synthèse, du regroupement des findings par niveau lisible
(CRITIQUE → À REVOIR → MINEUR), de l'échappement HTML et des styles
d'impression A4.

Exécution :
    python -m unittest tests.test_html_report -v
"""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scanner.models import Finding
from reports.html_report import generate_html, write_html_report

# Score synthétique (forme retournée par compute_score()).
def calc_score():
    return {
        "score": 49,
        "grade": "D",
        "total_findings": 3,
        "files_scanned": 10,
        "security": 2,
        "quality": 1,
        "performance": 0,
        "by_level": {"CRITIQUE": 1, "À REVOIR": 1, "MINEUR": 1},
        "by_domain_pct": {"security": 66.7, "quality": 33.3, "performance": 0.0},
        "weights": {"critical": 5, "high": 2, "medium": 1, "low": 0.5},
    }


def finding(**over):
    base = dict(
        file="src/app.py",
        line=12,
        rule_id="py-dangerous-eval",
        category="security_misc",
        severity="critical",
        title="Fonction eval() sur entrée utilisateur",
        description="Évaluation de code arbitraire possible.",
        recommendation="Éviter eval()",
        snippet="eval(user_input)",
        language="python",
    )
    base.update(over)
    return Finding(**base)


def default_findings():
    return [
        finding(),
        finding(file="server.js", line=5, rule_id="generic-cors",
                severity="high", category="security_misc",
                title="CORS permissif"),
        finding(file="db.js", rule_id="perf-blocking", severity="medium",
                category="performance", title="I/O synchrone"),
    ]


META = {"tool": "CodeScan", "version": "1.1.0",
        "timestamp": "2026-08-08T10:00:00", "target": "D:/projet"}


def page_for(findings=None, score=True):
    """Génère la page HTML avec ou sans note de score."""
    findings = default_findings() if findings is None else findings
    stats = {"files_scanned": 10, "by_category": {}}
    return generate_html(findings, stats, "D:/projet", META,
                         calc_score() if score else None)


class TestHero(unittest.TestCase):
    """Bloc de note : score, barre de progression, lettre colorée."""

    def test_score_number_present(self):
        self.assertIn("score-num\">49</span>", page_for())

    def test_grade_letter_present(self):
        self.assertIn("hero-grade", page_for())
        self.assertIn(">D</div>", page_for())

    def test_progress_bar_width_matches_score(self):
        self.assertIn("width:49%", page_for())

    def test_no_hero_without_score(self):
        # Le nom de classe apparaît aussi dans le CSS : on cible le balisage
        # réel du bloc, pas la feuille de style.
        self.assertNotIn('class="hero-score"', page_for(score=False))
        self.assertNotIn('class="hero-grade"', page_for(score=False))


class TestSummaryCards(unittest.TestCase):
    def test_card_labels(self):
        page = page_for()
        for label in ("Relevés", "Critiques", "À revoir", "Fichiers",
                      "Sécurité", "Qualité", "Performance"):
            self.assertIn(label, page)

    def test_card_counts(self):
        page = page_for()
        self.assertIn("card-num\">3</div>", page)    # total relevés
        self.assertIn("card-num\">1</div>", page)    # 1 critique + 1 à revoir
        self.assertIn("card-num\">10</div>", page)   # fichiers analysés

    def test_cards_omitted_without_score(self):
        self.assertNotIn("class=\"cards\"", page_for(score=False))


class TestLevels(unittest.TestCase):
    """Groupement des findings par niveau lisible + ordre du rapport."""

    def setUp(self):
        self.page = page_for()

    def test_level_headers(self):
        # Les 3 niveaux sont toujours affichés, même vides (parité Herald).
        for level in ("CRITIQUE", "À REVOIR", "MINEUR"):
            self.assertIn(level, self.page)

    def test_ordering_critique_first(self):
        i_crit = self.page.index("CRITIQUE")
        i_rev = self.page.index("À REVOIR")
        i_min = self.page.index("MINEUR")
        self.assertLess(i_crit, i_rev)
        self.assertLess(i_rev, i_min)

    def test_rule_badge_and_loc(self):
        self.assertIn("py-dangerous-eval", self.page)
        self.assertIn("src/app.py:12", self.page)

    def test_snippet_pre(self):
        self.assertIn("<pre class='snip'>eval(user_input)</pre>", self.page)

    def test_recommendation_line(self):
        self.assertIn("Correction : Éviter eval()", self.page)

    def test_empty_level_shows_message(self):
        # MINEUR n'a aucun finding ici : le message d'absence est affiché.
        self.assertIn("Aucun relevé de ce niveau", self.page)


class TestEscaping(unittest.TestCase):
    def test_finding_fields_escaped(self):
        f = finding(title="<script>alert()</script>", snippet="a < b")
        page = page_for([f])
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>alert()</script>", page)
        self.assertIn("<pre class='snip'>a &lt; b</pre>", page)


class TestPrintCss(unittest.TestCase):
    def test_a4_page_rule(self):
        page = page_for()
        self.assertIn("@page", page)
        self.assertIn("size: A4", page)

    def test_break_inside_avoid(self):
        page = page_for()
        self.assertIn("break-inside: avoid", page)

    def test_print_color_adjust(self):
        page = page_for()
        self.assertIn("print-color-adjust: exact", page)


class TestWriteFile(unittest.TestCase):
    def test_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "rapport.html")
            write_html_report(default_findings(), {}, "D:/projet", META,
                              out, calc_score())
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("CodeScan", content)
            self.assertIn("<html", content)


if __name__ == "__main__":
    unittest.main()
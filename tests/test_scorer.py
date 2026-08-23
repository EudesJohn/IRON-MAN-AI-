"""Tests du module de score (scanner/scorer.py) et du barème de lettres."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scanner.models import Finding
from scanner.scorer import compute_score, WEIGHTS, SCORE_K
from scanner.thresholds import THRESHOLDS, domain_of, grade_for


def finding(severity: str, category: str = "code_quality") -> Finding:
    """Un Finding minimal pour les tests de score."""
    return Finding(
        file="app.py", line=1, rule_id="test-rule", severity=severity,
        category=category,
    )


def make(counts: dict, files: int):
    """Construit une liste de findings à partir de compteurs par sévérité."""
    out = []
    for sev, n in counts.items():
        out.extend(finding(sev) for _ in range(n))
    return out, files


class TestComputeScore(unittest.TestCase):

    def test_empty_project_is_100_A(self):
        score = compute_score([], 100)
        self.assertEqual(score["score"], 100)
        self.assertEqual(score["grade"], "A")

    def test_no_files_is_100(self):
        score = compute_score([], 0)
        self.assertEqual(score["score"], 100)

    def test_herald_reference_lands_in_45_52(self):
        """Fixture simulant le projet analysé par Herald (~850 résultats sur
        78 fichiers) : le score doit rester autour de 49/100."""
        findings, files = make(
            {"critical": 1, "high": 400, "medium": 430, "low": 19}, files=78
        )
        score = compute_score(findings, files)
        self.assertGreaterEqual(score["score"], 45)
        self.assertLessEqual(score["score"], 52)

    def test_more_findings_lowers_score(self):
        base = compute_score(make({"low": 10}, 20)[0], 20)["score"]
        worse = compute_score(make({"low": 60}, 20)[0], 20)["score"]
        self.assertLess(worse, base)

    def test_higher_severity_lowers_score(self):
        low = compute_score(make({"low": 20}, 20)[0], 20)["score"]
        high = compute_score(make({"high": 20}, 20)[0], 20)["score"]
        self.assertLess(high, low)

    def test_critical_ratio_penalizes(self):
        """Sur un projet minuscule, une faille critique doit faire chuter
        le score nettement plus qu'une faille basse de même poids brute."""
        crit = compute_score(make({"critical": 1}, 5)[0], 5)["score"]
        low = compute_score(make({"low": 5}, 5)[0], 5)["score"]
        self.assertLess(crit, low)

    def test_score_clamped_0_100(self):
        s01 = compute_score(make({"high": 5000}, 1)[0], 1)["score"]
        self.assertGreaterEqual(s01, 0)
        self.assertLessEqual(s01, 100)

    def test_domains_and_levels_counted(self):
        findings = [
            finding("critical", "injection"),
            finding("high", "code_quality"),
            finding("medium", "performance"),
        ]
        score = compute_score(findings, 3)
        self.assertEqual(score["security"], 1)
        self.assertEqual(score["quality"], 1)
        self.assertEqual(score["performance"], 1)
        self.assertEqual(score["by_level"]["CRITIQUE"], 1)
        self.assertEqual(score["by_level"]["À REVOIR"], 2)

    def test_by_domain_pct_sums_close_to_100(self):
        findings = [
            finding("high", "injection"),
            finding("medium", "code_quality"),
            finding("low", "performance"),
        ]
        score = compute_score(findings, 10)
        total_pct = round(
            sum(score["by_domain_pct"].values()), 1
        )
        self.assertAlmostEqual(total_pct, 100.0, delta=0.1)


class TestThresholds(unittest.TestCase):

    def test_grade_bands_reproduce_herald(self):
        """« 49/100 D » : un score de 49 reçoit la lettre D (grille 5 crans)."""
        self.assertEqual(grade_for(49), "D")
        self.assertEqual(grade_for(90), "A")
        self.assertEqual(grade_for(39), "F")

    def test_domain_of_known_categories(self):
        self.assertEqual(domain_of("sql"), "security")  # injection
        self.assertEqual(domain_of("code_quality"), "quality")
        self.assertEqual(domain_of("performance"), "performance")
        self.assertEqual(domain_of("injection"), "security")
        self.assertEqual(domain_of("secrets"), "security")

    def test_threshold_keys(self):
        for key in ("function_lines", "cyclomatic_complexity",
                    "cognitive_complexity", "nesting_depth", "max_params",
                    "line_length", "file_lines"):
            self.assertIn(key, THRESHOLDS)


if __name__ == "__main__":
    unittest.main()
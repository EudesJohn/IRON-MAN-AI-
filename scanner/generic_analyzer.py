"""Analyseur générique multi-langage (regex + heuristiques).

Applique aux fichiers source non-Python (et à certains fichiers Python)
les patterns de rules/patterns.json : injection SQL, XSS, eval/unserialize,
exécution de commandes, secrets en dur, TODO/PIXME, CORS permissif, ReDoS…

Depuis la 1.1, les métriques de qualité de fonction (longueur, complexité
cyclomatique…) sont calculées par `scanner/quality_analyzer.py`, et les
entrées `builtin` ont disparu du catalogue par défaut. Le support « builtin »
ci-dessous est conservé en rétro-compatibilité : si une base de patterns
personnalisée référence encore `builtin: long_function` ou
`builtin: cyclomatic_complexity`, ces règles restent calculables ici.
"""

import bisect
import re

from scanner.models import Finding

# Seuils des heuristiques de qualité de code (rétro-compat « builtin »).
MAX_FUNCTION_LINES = 80
MAX_COMPLEXITY = 12

# Langages analysés par équilibrage d'accolades.
BRACE_LANGS = {
    "javascript", "typescript", "php", "java", "csharp", "go", "kotlin",
    "scala", "rust", "swift", "c", "cpp",
}

# Regex des points de décision pour la complexité cyclomatique.
DECISION_RE = re.compile(
    r"\b(if|else\s+if|for|while|switch|case|catch)\b|\b(&&|\|\|)\b|\?\s",
    re.IGNORECASE,
)

# Indices qu'un bloc `{…}` ouvre une fonction.
FUNCTION_KW_RE = re.compile(r"\b(function|fn|func|def)\b")
MODIFIER_RE = re.compile(
    r"\b(public|private|protected|static|final|async|internal|export|"
    r"const|let|var|override|abstract)\b"
)
PARAMS_RE = re.compile(r"[\w)\]]\s*\([^(){};]*\)\s*$")


def _line_of(line_starts, pos):
    """Numéro de ligne (1-based) d'une position dans le contenu."""
    return bisect.bisect_right(line_starts, pos)


class GenericAnalyzer:
    """Analyse le contenu d'un fichier source avec les patterns génériques."""

    def __init__(self, patterns: list, verbose: bool = False):
        self.verbose = verbose
        self._compiled = []      # (meta, regex) pour les règles regex
        self._builtin = []       # meta pour les règles calculées en code
        for meta in patterns:
            pattern = meta.get("pattern")
            if pattern:
                try:
                    rx = re.compile(pattern)
                except re.error as exc:
                    print(f"[generic] pattern invalide {meta.get('id')} : {exc}")
                    continue
                self._compiled.append((meta, rx))
            elif meta.get("builtin"):
                self._builtin.append(meta)

    # ------------------------------------------------------------------
    def analyze(self, sf, content: str) -> list:
        """Analyse un fichier source et renvoie les findings génériques."""
        findings = []
        line_starts = _build_line_starts(content)
        lines = content.splitlines()

        # 1. Patterns regex
        for meta, rx in self._compiled:
            languages = meta.get("languages")
            if languages and sf.language not in languages:
                continue
            for m in rx.finditer(content):
                line = _line_of(line_starts, m.start())
                findings.append(self._make_finding(
                    meta, sf, line, lines, snippet=self._snippet(lines, line),
                ))

        # 2. Règles calculées en code (complexité / longueur de fonction)
        for meta in self._builtin:
            languages = meta.get("languages")
            if languages and sf.language not in languages:
                continue
            if meta.get("builtin") == "long_function":
                findings.extend(
                    self._long_functions(meta, sf, content, line_starts, lines)
                )
            elif meta.get("builtin") == "cyclomatic_complexity":
                findings.extend(
                    self._high_complexity(meta, sf, content, line_starts, lines)
                )

        return findings

    # ------------------------------------------------------------------
    # Heuristiques code-quality
    # ------------------------------------------------------------------
    def _function_blocks(self, content):
        """Renvoie [(start, end)] des blocs `{…}` ressemblant à des fonctions."""
        stack = []
        blocks = []
        for i, ch in enumerate(content):
            if ch == "{":
                stack.append(i)
            elif ch == "}" and stack:
                start = stack.pop()
                if self._is_function_block(content, start):
                    blocks.append((start, i))
        return blocks

    def _is_function_block(self, content, start) -> bool:
        """True si le bloc `{` en position `start` ouvre une fonction."""
        pre = content[max(0, start - 80):start]
        if FUNCTION_KW_RE.search(pre):
            return True
        # Flèches JS/TS : `=>` juste avant `{`
        if re.search(r"=>\s*$", pre):
            return True
        # Méthodes de classe : `) {` précédé d'un modificateur
        if PARAMS_RE.search(pre) and MODIFIER_RE.search(pre):
            return True
        return False

    def _long_functions(self, meta, sf, content, line_starts, lines):
        out = []
        for start, end in self._function_blocks(content):
            nlines = _line_of(line_starts, end) - _line_of(line_starts, start) + 1
            if nlines > MAX_FUNCTION_LINES:
                out.append(self._make_finding(
                    meta, sf, _line_of(line_starts, start), lines,
                    extra=(
                        f"Fonction de {nlines} lignes "
                        f"(seuil : {MAX_FUNCTION_LINES})."
                    ),
                ))
        return out

    def _high_complexity(self, meta, sf, content, line_starts, lines):
        out = []
        for start, end in self._function_blocks(content):
            body = content[start:end + 1]
            complexity = 1 + sum(1 for _ in DECISION_RE.finditer(body))
            if complexity > MAX_COMPLEXITY:
                out.append(self._make_finding(
                    meta, sf, _line_of(line_starts, start), lines,
                    extra=(
                        f"Complexité estimée : {complexity} "
                        f"(seuil : {MAX_COMPLEXITY})."
                    ),
                ))
        return out

    # ------------------------------------------------------------------
    @staticmethod
    def _make_finding(meta, sf, line, lines, snippet="", extra=""):
        """Construit un Finding à partir des métadonnées d'une règle."""
        description = meta.get("description", "")
        if extra:
            description = f"{extra} {description}".strip()
        return Finding(
            file=sf.relpath, line=line,
            rule_id=meta.get("id", "generic-rule"),
            category=meta.get("category", "security_misc"),
            severity=meta.get("severity", "medium"),
            title=meta.get("title", "Règle générique"),
            description=description,
            recommendation=meta.get("recommendation", ""),
            snippet=snippet,
            language=sf.language, source="generic_analyzer",
        )

    @staticmethod
    def _snippet(lines, lineno, width=140):
        if 0 < lineno <= len(lines):
            return lines[lineno - 1][:width].strip()
        return ""


def _build_line_starts(content: str):
    """Offsets de début de ligne pour un accès au numéro de ligne O(log n)."""
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts

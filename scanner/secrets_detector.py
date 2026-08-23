"""Détection de secrets : patterns forts (regex) + entropie de Shannon.

Ce module scanne le contenu brut de tous les fichiers texte :
  - des patterns « forts » (clés AWS, tokens GitHub/Stripe/Slack, clés
    privées…) définis dans rules/patterns.json ;
  - les chaînes à forte entropie de Shannon, caractéristique d'une clé
    ou d'un jeton généré aléatoirement ;
  - les mots de passe/tokens en clair dans les fichiers de configuration
    (.env, .json, .yml, .ini…) committés.
"""

import math
import re
import bisect

from scanner.models import Finding

# Seuil d'entropie au-delà duquel une chaîne est jugée suspecte (sur 8 max).
ENTROPY_THRESHOLD = 4.5
# Longueur minimale d'une chaîne candidate à la détection par entropie.
MIN_ENTROPY_LEN = 16

# Valeurs « factices » fréquentes dans les exemples/documentations : on les
# ignore pour éviter les faux positifs. Attention aux frontières de mots :
# « CYEXAMPLEKEY » (exemple officiel AWS) ne doit PAS être filtré.
PLACEHOLDER_PATTERN = re.compile(
    r"\b(your|xxxxx*|changeme|change[_-]?me|dummy|placeholder|sample|"
    r"replace_?me|put_?your)\b|<[^>]+>|\{\{.*\}\}",
    re.IGNORECASE,
)

# Chaînes purement hexadécimales (UUID, hachages) : pas des secrets a priori.
HEX_ONLY = re.compile(r"^[0-9a-fA-F]{16,}$")

# Clés des fichiers de configuration considérées comme des secrets.
CONFIG_SECRET_KEY = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|"
    r"access[_-]?key|client[_-]?secret|private[_-]?key)",
    re.IGNORECASE,
)

# Expression des littéraux de chaîne candidats à l'analyse d'entropie.
STRING_LITERAL_RE = re.compile(r"""["'][A-Za-z0-9_\-./+=]{16,}["']""")


def shannon_entropy(text: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne (en bits par caractère).

    Une valeur proche de 4-5+ bits/caractère indique une distribution
    quasi-aléatoire, typique des clés et jetons générés.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _line_of(line_starts, pos):
    """Numéro de ligne (1-based) d'une position dans le contenu."""
    return bisect.bisect_right(line_starts, pos)


def _build_line_starts(content: str):
    """Pré-calcule les offsets de début de ligne pour un accès O(log n)."""
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


class SecretsDetector:
    """Détecte les secrets dans le contenu brut d'un fichier."""

    def __init__(self, patterns: list, verbose: bool = False):
        self.verbose = verbose
        self._compiled = []
        for meta in patterns:
            pattern = meta.get("pattern")
            if not pattern:          # règles « builtin » (entropie…)
                continue
            try:
                rx = re.compile(pattern)
            except re.error as exc:
                print(f"[secrets] pattern invalide {meta.get('id')} : {exc}")
                continue
            self._compiled.append((meta, rx))

    def detect(self, sf, content: str) -> list:
        """Analyse le contenu d'un fichier et renvoie les findings secrets."""
        findings = []
        line_starts = _build_line_starts(content)
        lines = content.splitlines()

        # 1. Patterns forts (regex) : un format de secret reconnu est
        #    toujours signalé — c'est au relecteur de confirmer ou non.
        for meta, rx in self._compiled:
            for m in rx.finditer(content):
                line = _line_of(line_starts, m.start())
                findings.append(Finding(
                    file=sf.relpath, line=line,
                    rule_id=meta.get("id", "secret-unknown"),
                    category="secrets",
                    severity=meta.get("severity", "high"),
                    title=meta.get("title", "Secret exposé"),
                    description=meta.get("description", ""),
                    recommendation=meta.get("recommendation", ""),
                    snippet=lines[line - 1][:140].strip(),
                    language=sf.language, source="secrets_detector",
                ))

        # 2. Entropie de Shannon (chaînes suspectes)
        findings.extend(self._detect_entropy(sf, content, lines, line_starts))

        # 3. Secrets en clair dans les fichiers de configuration
        if sf.kind == "config":
            findings.extend(self._detect_config(sf, lines))

        return findings

    # ------------------------------------------------------------------
    def _detect_entropy(self, sf, content, lines, line_starts):
        """Repère les chaînes à forte entropie (probables clés/jetons)."""
        out = []
        for m in STRING_LITERAL_RE.finditer(content):
            candidate = m.group(0)[1:-1]   # retire les guillemets
            if len(candidate) < MIN_ENTROPY_LEN:
                continue
            # Exclusions : placeholders, hachages hex, URLs, mots courants.
            if PLACEHOLDER_PATTERN.search(candidate):
                continue
            if HEX_ONLY.fullmatch(candidate):
                continue
            if "://" in candidate or " " in candidate:
                continue
            if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
                line = _line_of(line_starts, m.start())
                out.append(Finding(
                    file=sf.relpath, line=line,
                    rule_id="secret-high-entropy", category="secrets",
                    severity="low", title="Possible clé/secret (forte entropie)",
                    description=(
                        "Chaîne de longueur significative avec une entropie de "
                        "Shannon élevée — caractéristique d'un secret généré."
                    ),
                    recommendation=(
                        "Vérifier la nature de cette valeur ; si c'est un secret, "
                        "le déplacer dans l'environnement ou un coffre-fort."
                    ),
                    snippet=lines[line - 1][:140].strip(),
                    language=sf.language, source="secrets_detector",
                ))
        return out

    def _detect_config(self, sf, lines):
        """Mots de passe/tokens en clair dans .env, .json, .yml, .ini…"""
        out = []
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "<!--")):
                continue
            if "=" not in stripped and ":" not in stripped:
                continue
            # On ne teste que la CLÉ (à gauche de `=` / `:`) et non la ligne
            # entière : sinon un nom de paquet ou une URL contenant « token »
            # (ex. `@csstools/css-tokenizer` dans package-lock.json) génère un
            # faux positif.
            key = self._extract_key(stripped)
            if not key or not CONFIG_SECRET_KEY.search(key):
                continue

            value = self._extract_value(stripped)
            if self._is_placeholder_value(value):
                continue

            out.append(Finding(
                file=sf.relpath, line=i,
                rule_id="config-plaintext-secret", category="secrets",
                severity="high", title="Secret en clair dans un fichier de config",
                description=(
                    "Un mot de passe, une clé ou un token est présent en clair "
                    "dans un fichier de configuration committé au dépôt."
                ),
                recommendation=(
                    "Supprimer ce fichier de l'historique, utiliser des variables "
                    "d'environnement ou un gestionnaire de secrets, et révoquer "
                    "le secret exposé."
                ),
                snippet=stripped[:140], language=sf.language,
                source="secrets_detector",
            ))
        return out

    @staticmethod
    def _extract_key(line: str) -> str:
        """Extrait la clé d'une ligne `KEY=value` ou `"key": "value"`."""
        # format clé=valeur (.env, ini)
        if "=" in line:
            return line.split("=", 1)[0].strip().strip('"')
        # format JSON `"clé": "valeur"` ou YAML `clé: valeur`.
        # La classe exclut `/`, `@`… : une clé de package-lock.json
        # (ex. `node_modules/jsonwebtoken`) n'est jamais retenue.
        m = re.match(r'\s*"?([A-Za-z0-9_.\-]+)"?\s*:', line)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _extract_value(line: str) -> str:
        """Extrait la valeur d'une ligne `KEY=value` ou `"key": "value"`."""
        # format clé=valeur
        if "=" in line and ":" not in line:
            return line.split("=", 1)[1].strip()
        # format "key": "value"
        m = re.search(r"""[:"'\s]+\s*["']([^"']+)["']""", line)
        if m:
            return m.group(1).strip()
        return ""

    @staticmethod
    def _is_placeholder_value(value: str) -> bool:
        """True si la valeur ressemble à un placeholder (faux positif).

        NB : le mot « example » n'est pas filtré — l'exemple officiel AWS
        « …CYEXAMPLEKEY » doit rester signalé pour relecture.
        """
        if not value:
            return True
        v = value.strip()
        if len(v) < 2:
            return True
        # Référence de variable d'environnement (`$VAR`, `${VAR:-}`, `%VAR%`) :
        # ce n'est pas une valeur secrète en clair.
        if v.startswith(("$", "%")):
            return True
        if re.fullmatch(r"<[^>]+>", v):            # <your-password>
            return True
        if re.fullmatch(r"[?xX*.\s]+", v):          # xxx, ****…
            return True
        if re.search(r"(\.\.\.|\btodo\b)", v, re.I):
            return True
        if len(v) <= 6 and PLACEHOLDER_PATTERN.search(v):
            return True
        return False

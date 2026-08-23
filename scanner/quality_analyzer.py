"""Analyseur de qualité multi-langage (parité Herald).

Ajoute à CodeScan les métriques de qualité de code et de performance qui
manquent par rapport à des outils comme Herald :
  - métriques de fonction : longueur, cyclomatique, complexité cognitive,
    imbrication, nombre de paramètres ;
  - règles par ligne : ligne trop longue, fichier trop long, code commenté ;
  - règles async/performance JavaScript : I/O synchrone bloquante, I/O dans
    une boucle (N+1), boucles quadratiques (O(n²)) ;
  - règles de débogage JS : console.log, alert/confirm, clone JSON.

Repose sur un lexeur maison (sans dépendance) qui masque les chaînes,
templates et commentaires pour éviter les faux positifs, et sur
l'équilibrage d'accolades pour délimiter les fonctions et blocs.
Les valeurs calculées sont indicatives (heuristiques), pas des certitudes.
"""

import bisect
import re

from scanner.models import Finding
from scanner.thresholds import threshold

# Langages analysés par équilibrage d'accolades pour les métriques de fonction.
BRACE_LANGS = {
    "javascript", "typescript", "php", "java", "csharp", "go", "kotlin",
    "scala", "rust", "swift", "c", "cpp",
}

# Préfixes courts pour les identifiants de règles (lisibles dans le rapport).
LANG_PREFIX = {
    "python": "py", "javascript": "js", "typescript": "ts", "php": "php",
    "java": "java",
    "csharp": "csharp", "go": "go", "kotlin": "kotlin", "scala": "scala",
    "rust": "rust", "swift": "swift", "c": "c", "cpp": "cpp",
}

# Mots-clés de décision (complexité cyclomatique et cognitive).
DECISION_RE = re.compile(
    r"\b(?:if|else\s+if|elseif|for|while|switch|case|catch|do)\b", re.I
)

# I/O synchrones bloquantes (Node, PHP…).
SYNC_IO_RE = re.compile(
    r"\b(?:readFileSync|writeFileSync|appendFileSync|readdirSync|mkdirSync|"
    r"rmSync|renameSync|copyFileSync|unlinkSync|existsSync|statSync|lstatSync|"
    r"execSync|spawnSync|querySync|readSync|writeSync)\s*\("
)

# Fonctions de « configuration » : une I/O synchrone y est tolérée (chargement
# de config au démarrage) — anti-faux-positifs.
CONFIG_FN_NAMES = re.compile(
    r"\b(?:config|configure|init|setup|load|main|bootstrap)\b", re.I
)

# Appels réseau/SQL dans une boucle (I/O N+1).
IO_IN_LOOP_RE = re.compile(
    r"\bawait\b|\bfetch\s*\(|\baxios\b|\.(?:get|post|put|delete|request)\s*\(|"
    r"\b(?:query|findOne|find|insert|update|create|save)\s*\("
)
PROMISE_ALL_RE = re.compile(r"Promise\.all\s*\(|Promise\.allSettled\s*\(")

# Recherche linéaire d'un tableau à l'intérieur d'une boucle (O(n²)).
LINEAR_SEARCH_RE = re.compile(
    r"\.(?:includes|indexOf|find|some|findIndex)\s*\("
)
LITERAL_ARG_RE = re.compile(
    r"\.(?:includes|indexOf|find|some|findIndex)\s*\((?:'[^']*'|\"[^\"]*\"|\`[^\`]*\`)"
)

# Délimitation des boucles for/while et callbacks de tableau.
LOOP_HEADER_RE = re.compile(
    r"\b(for|while)\s*\([^{}]*\)\s*\{|\.(forEach|map|filter|reduce)\s*\("
)

# Règles JS « débogage ».
DEBUG_CONSOLE_RE = re.compile(r"\bconsole\.(?:log|debug|info)\s*\(")
ALERT_RE = re.compile(r"\b(?:alert|confirm|prompt)\s*\(")
DEEP_CLONE_RE = re.compile(r"JSON\.parse\s*\(\s*JSON\.stringify\s*\(")

# Égalité lâche (== !=) — hors ===, !==, =>.
LOOSE_EQ_RE = re.compile(r"(?<![=!<>&|])==(?!=)|(?<![=!])!=(?!=)")
# Booléens redondants (x === true, x == false, return x ? true : false…).
REDUNDANT_BOOL_RE = re.compile(
    r"(?:===|==|!==|!=)\s*(?:true|false)\b|(?:true|false)\s*(?:===|==)"
)

# Nombres magiques : valeurs tolérées (ne pas signaler).
MAGIC_SKIP = {
    "0", "1", "2", "3", "10", "100", "1000", "1024", "255", "-1",
}

# Seuil minimal de lignes de commentaires contiguës « qui ressemblent à du code ».
COMMENTED_MIN_LINES = 3

# Contexte interdit pour un bloc de commentaires (licence, documentation…).
LICENSE_HINTS = re.compile(
    r"\b(copyright|license|@license|all rights reserved|spdx|"
    r"MIT|apache|gnu|gpl|bsd|created|author)\b", re.I
)


# ---------------------------------------------------------------------------
# Outils communs
# ---------------------------------------------------------------------------

def _build_line_starts(content: str):
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_no(line_starts, pos: int) -> int:
    """Numéro de ligne (1-based) d'une position dans le contenu."""
    return bisect.bisect_right(line_starts, pos)


# ---------------------------------------------------------------------------
# Lexeur : masque les régions hors-code (strings, templates, commentaires)
# ---------------------------------------------------------------------------

class Lexer:
    """Masque les zones non-code d'un fichier pour éviter les faux positifs.

    `code_str` est une chaîne de même longueur que le contenu, où les
    caractères hors-code sont remplacés par des espaces (positions conservées).
    `comments` est la liste des (debut, fin) des blocs commentaires.
    """

    def __init__(self, content: str, hash_comment: bool = False):
        self.content = content
        self.n = len(content)
        self.mask = bytearray(b"c") * len(content)
        self.comments = []
        self.hash_comment = hash_comment  # '#' est un commentaire (py/php/ruby)
        self._scan()
        self.code_str = "".join(
            content[i] if self.mask[i] == ord("c") else " "
            for i in range(len(content))
        )

    def _hide(self, a: int, b: int):
        for k in range(max(0, a), min(b, self.n)):
            self.mask[k] = ord("h")

    def _scan(self):
        content = self.content
        n = self.n
        i = 0
        while i < n:
            ch = content[i]
            if ch == "/" and i + 1 < n and content[i + 1] == "/":
                end = content.find("\n", i)
                end = n if end == -1 else end
                self._hide(i, end)
                self.comments.append((i, end))
                i = end
            elif ch == "#" and self.hash_comment:
                end = content.find("\n", i)
                end = n if end == -1 else end
                self._hide(i, end)
                self.comments.append((i, end))
                i = end
            elif ch == "/" and i + 1 < n and content[i + 1] == "*":
                end = content.find("*/", i + 2)
                end = n if end == -1 else end + 2
                self._hide(i, end)
                self.comments.append((i, end))
                i = end
            elif ch in "\"'`":
                i = self._string(i)
            else:
                i += 1

    def _string(self, i: int) -> int:
        """Masque une string ('', \"\") ou un template (`…`), retourne la fin."""
        content = self.content
        quote = content[i]
        j = i + 1
        escaped = False
        while j < self.n:
            c = content[j]
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == quote:
                j += 1
                break
            elif c == "\n":
                break
            j += 1
        self._hide(i, j)
        return j


# ---------------------------------------------------------------------------
# Analyseur
# ---------------------------------------------------------------------------

class QualityAnalyzer:
    """Analyse les métriques de qualité et de performance d'un fichier."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------
    def analyze(self, sf, content: str) -> list:
        """Analyse un fichier et renvoie les findings de qualité."""
        raw_lines = content.splitlines()
        self._raw_lines = raw_lines  # pour les snippets (texte réel)
        findings = []

        # Règles par-ligne communes à tous les langages.
        self._long_line(findings, sf, raw_lines)
        self._file_too_long(findings, sf, len(raw_lines))

        if sf.kind == "python":
            # Les métriques de fonction Python sont calculées à l'AST
            # (scanner/python_analyzer.py) ; ici : code commenté seulement.
            lexer = Lexer(content, hash_comment=True)
            self._commented_out_code(findings, sf, lexer)
            return findings

        lexer = Lexer(content, hash_comment=(sf.language in ("python", "php", "ruby")))
        code = lexer.code_str

        self._commented_out_code(findings, sf, lexer)

        if sf.language in BRACE_LANGS:
            self._function_metrics(findings, sf, code)

        if sf.language in ("javascript", "typescript"):
            self._js_rules(findings, sf, code, content)

        if sf.language in ("javascript", "typescript", "php"):
            self._brace_block_rules(findings, sf, code)

        return findings

    # ------------------------------------------------------------------
    # Helper de construction d'un Finding
    # ------------------------------------------------------------------
    def _f(self, sf, line, rule_id, severity, category, title, description,
           recommendation="", snippet=""):
        return Finding(
            file=sf.relpath, line=line, rule_id=rule_id, category=category,
            severity=severity, title=title, description=description,
            recommendation=recommendation, snippet=snippet,
            language=sf.language, source="quality_analyzer",
        )

    @staticmethod
    def _prefix(sf) -> str:
        return LANG_PREFIX.get(sf.language, sf.language)

    def _snippet(self, line, width=140):
        """Extrait la ligne brute (texte réel, pas masqué) à partir du n° de ligne."""
        if 0 < line <= len(self._raw_lines):
            return self._raw_lines[line - 1][:width].strip()
        return ""

    # ------------------------------------------------------------------
    # Règles ligne par ligne
    # ------------------------------------------------------------------
    def _long_line(self, findings, sf, raw_lines):
        limit = threshold("line_length")
        prefix = self._prefix(sf)
        for i, line in enumerate(raw_lines):
            length = len(line)
            if length <= limit:
                continue
            stripped = line.lstrip()
            # Anti-FP : commentaire/URL longue → ignore.
            if stripped.startswith(("#", "//", "*", "/*")):
                continue
            if "://" in line and ('"' in line or "'" in line):
                continue
            findings.append(self._f(
                sf, i + 1, f"{prefix}-long-line", "low", "code_quality",
                "Ligne trop longue",
                f"Cette ligne fait {length} caractères (max {limit}).",
                "La découper pour la lisibilité.",
                snippet=line[:140],
            ))

    def _file_too_long(self, findings, sf, n_lines):
        limit = threshold("file_lines")
        if n_lines <= limit:
            return
        findings.append(self._f(
            sf, 1, f"{self._prefix(sf)}-file-too-long", "low", "code_quality",
            "Fichier trop long",
            f"Ce fichier contient {n_lines} lignes (max {limit}).",
            "Le découper en modules plus petits.",
        ))

    # ------------------------------------------------------------------
    # Métriques de fonction (équilibrage d'accolades)
    # ------------------------------------------------------------------
    def _brace_pairs(self, code: str) -> dict:
        """Renvoie {pos_ouvrante : pos_fermante} des blocs `{…}` du code."""
        stack = []
        pairs = {}
        for i, ch in enumerate(code):
            if ch == "{":
                stack.append(i)
            elif ch == "}" and stack:
                pairs[stack.pop()] = i
        return pairs

    def _function_blocks(self, code: str):
        """Renvoie [(start, end, name, n_params)] des blocs « fonctions »."""
        pairs = self._brace_pairs(code)
        blocks = []
        for start in sorted(pairs):
            pre = code[max(0, start - 140):start]
            if not self._is_function_block(pre):
                continue
            blocks.append((
                start, pairs[start],
                self._function_name(pre), self._function_params(pre),
            ))
        return blocks

    @staticmethod
    def _is_function_block(pre: str) -> bool:
        # Exclut les blocs de contrôle purs : `if (…) {`, `while (…) {`…
        if re.search(r"\b(?:if|while|for|switch|catch|with)\s*\(", pre):
            return False
        if re.search(r"\b(?:function|fn|func|def)\b", pre):
            return True
        if re.search(r"=>\s*$", pre):
            return True
        # Méthode de classe / fonction nommée : `name(…) {` ou `name() {`
        if re.search(r"[\w)\]]\s*\([^(){};]*\)\s*$", pre):
            return True
        return False

    @staticmethod
    def _function_name(pre: str) -> str:
        m = re.search(r"function\s+(\w+)", pre)
        if m:
            return m.group(1)
        # `const f = … => {` ou `f = function…`
        m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?$", pre)
        if m:
            return m.group(1)
        # `name(…) {`
        m = re.search(r"([A-Za-z_$][\w$]*)\s*\([^(){};]*\)\s*$", pre)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _function_params(pre: str) -> int:
        idx = pre.rfind("(")
        if idx == -1:
            # Flèche sans parenthèse : `x => {` → 1 paramètre.
            if re.search(r"(?<![\w)\]])([A-Za-z_$][\w$]*)\s*=>\s*$", pre):
                return 1
            return 0
        depth = 0
        count = 1
        nonblank = False
        for ch in pre[idx:]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            elif ch == "," and depth == 1:
                count += 1
            elif ch not in " \t\n\r":
                nonblank = True
        return count if nonblank else 0

    @staticmethod
    def _body_metrics(body: str):
        """Approxime (cyclomatique, cognitive, imbrication) d'un corps."""
        cyclomatic = 1
        cognitive = 0
        depth = 0
        max_depth = 0
        n = len(body)
        i = 0
        while i < n:
            c = body[i]
            if c == "{":
                depth += 1
                if depth > max_depth:
                    max_depth = depth
                i += 1
                continue
            if c == "}":
                depth = max(depth - 1, 0)
                i += 1
                continue
            if c == "?" and i + 1 < n and body[i + 1] != "?":
                cognitive += 1 + depth
                cyclomatic += 1
                i += 1
                continue
            if body.startswith("&&", i) or body.startswith("||", i) or \
                    body.startswith("??", i):
                cognitive += 1 + depth
                cyclomatic += 1
                i += 2
                continue
            if body[i].isalpha() or body[i] == "_":
                m = DECISION_RE.match(body, i)
                if m:
                    cognitive += 1 + depth
                    cyclomatic += 1
                    i = m.end()
                    continue
            i += 1
        return cyclomatic, cognitive, max_depth

    def _function_metrics(self, findings, sf, code):
        line_starts = _build_line_starts(code)
        prefix = self._prefix(sf)
        for start, end, name, n_params in self._function_blocks(code):
            body = code[start + 1:end]
            n_lines = _line_no(line_starts, end) - _line_no(line_starts, start) + 1
            cyclomatic, cognitive, nesting = self._body_metrics(body)
            line = _line_no(line_starts, start)
            label = name or "anonyme"

            if n_lines > threshold("function_lines"):
                findings.append(self._f(
                    sf, line, f"{prefix}-function-too-long", "low",
                    "code_quality", f"Fonction trop longue ({label})",
                    f"Fonction trop longue : {n_lines} lignes "
                    f"(max {threshold('function_lines')}).",
                    "La découper en sous-fonctions plus petites.",
                ))
            if cyclomatic > threshold("cyclomatic_complexity"):
                findings.append(self._f(
                    sf, line, f"{prefix}-high-complexity", "medium",
                    "code_quality", f"Complexité cyclomatique élevée ({label})",
                    f"Complexité cyclomatique élevée : {cyclomatic} "
                    f"(max {threshold('cyclomatic_complexity')}).",
                    "Simplifier la logique ou extraire des fonctions.",
                ))
            if cognitive > threshold("cognitive_complexity"):
                findings.append(self._f(
                    sf, line, f"{prefix}-cognitive-complexity", "medium",
                    "code_quality", f"Complexité cognitive élevée ({label})",
                    f"Complexité cognitive élevée : {cognitive} "
                    f"(max {threshold('cognitive_complexity')}).",
                    "Aplatir l'imbrication avec des clauses de garde.",
                ))
            if nesting > threshold("nesting_depth"):
                findings.append(self._f(
                    sf, line, f"{prefix}-deep-nesting", "medium",
                    "code_quality", f"Imbrication excessive ({label})",
                    f"Imbrication excessive : {nesting} niveaux "
                    f"(max {threshold('nesting_depth')}).",
                    "Utiliser des retours anticipés ou extraire des fonctions.",
                ))
            if n_params > threshold("max_params"):
                findings.append(self._f(
                    sf, line, f"{prefix}-too-many-params", "medium",
                    "code_quality", f"Trop de paramètres ({label})",
                    f"Trop de paramètres : {n_params} (max {threshold('max_params')}).",
                    "Regrouper les arguments liés dans un objet/struct.",
                ))

    # ------------------------------------------------------------------
    # Code commenté
    # ------------------------------------------------------------------
    def _commented_out_code(self, findings, sf, lexer):
        if not lexer.comments:
            return
        line_starts = _build_line_starts(lexer.content)
        covered = set()
        for start, end in lexer.comments:
            a = _line_no(line_starts, start)
            b = _line_no(line_starts, end)
            covered.update(range(a, b + 1))

        raw_lines = lexer.content.splitlines()
        runs = []
        cur = None
        prev = None
        for line in sorted(covered):
            if cur is None:
                cur = prev = line
            elif line == prev + 1:
                prev = line
            else:
                runs.append((cur, prev))
                cur = prev = line
        if cur is not None:
            runs.append((cur, prev))

        for a, b in runs:
            if b - a + 1 < COMMENTED_MIN_LINES:
                continue
            texts = [raw_lines[i - 1] for i in range(a, b + 1)]
            if any(self._code_like(t) for t in texts):
                findings.append(self._f(
                    sf, a, f"{self._prefix(sf)}-commented-out-code", "low",
                    "code_quality", "Code commenté",
                    f"Code commenté (probablement mort) : {b - a + 1} lignes.",
                    "Le supprimer (Git garde l'historique).",
                ))
                return  # un seul par fichier

    @staticmethod
    def _code_like(line: str) -> bool:
        s = re.sub(r"^[#*/]+\s*", "", line.lstrip()).strip()
        if not s or len(s) < 6:
            return False
        if re.search(r"\b(?:TODO|FIXME|HACK|XXX)\b", s, re.I):
            return False
        if "http://" in s or "https://" in s:
            return False
        if LICENSE_HINTS.search(s) and not re.search(r"\b(return|if|for|const)\b", s):
            return False
        return bool(re.search(
            r"\b(if|for|while|return|function|const|let|var|class|def|"
            r"import|export|switch|case|try|catch)\b|=>|\{[^}]*\}",
            s,
        ))

    # ------------------------------------------------------------------
    # Règles JavaScript / TypeScript
    # ------------------------------------------------------------------
    def _loop_bodies(self, code: str):
        """Renvoie [(pos_du_corps, fin_du_corps, type)] des boucles."""
        pairs = self._brace_pairs(code)
        out = []
        for m in LOOP_HEADER_RE.finditer(code):
            head = m.group(0)
            if head.lstrip().startswith(("for", "while")):
                open_brace = m.end() - 1  # le `{` final
                close = pairs.get(open_brace)
                if close is None:
                    continue
                out.append((open_brace, close, head.lstrip()[:3]))
            else:
                # .forEach(…) → trouver `=>` puis le `{` du corps.
                arrow = code.find("=>", m.end())
                if arrow == -1:
                    continue
                open_brace = code.find("{", arrow)
                if open_brace == -1:
                    continue
                close = pairs.get(open_brace)
                if close is None:
                    continue
                out.append((open_brace, close, "forEach"))
        return out

    @staticmethod
    def _inside_promise_all(code: str, start: int, end: int) -> bool:
        """True si le segment [start, end] est à l'intérieur d'un Promise.all()."""
        idx = code.rfind("Promise.all", 0, start)
        if idx == -1:
            return False
        depth = 0
        for k in range(idx, end):
            c = code[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            if depth < 0:
                return False
        return depth > 0

    def _js_rules(self, findings, sf, code, raw=""):
        """Règles JS/TS. `code` est le code masqué (strings→espaces), `raw` le
        contenu d'origine : positions identiques, mais le texte des littéraux
        est intact dans `raw` (nécessaire pour la règle des littéraux)."""
        prefix = self._prefix(sf)
        line_starts = _build_line_starts(code)
        blocks = self._function_blocks(code)

        def in_config_context(pos: int) -> bool:
            for start, end, name, _ in blocks:
                if start < pos <= end:
                    return bool(name and CONFIG_FN_NAMES.search(name))
            return True  # hors fonction : chargement de config au top-level

        # --- I/O synchrone bloquante -----------------------------------
        for m in SYNC_IO_RE.finditer(code):
            pos = m.start()
            if in_config_context(pos):
                continue
            line = _line_no(line_starts, pos)
            call = m.group(0).rstrip("(")
            findings.append(self._f(
                sf, line, "perf-blocking-sync-io", "high", "performance",
                "I/O synchrone bloquante",
                f"Appel d'entrée/sortie synchrone bloquante : {call}().",
                "Utiliser la version asynchrone (fs.promises / await).",
            ))

        # --- I/O dans une boucle (N+1) ----------------------------------
        loops = self._loop_bodies(code)
        for open_brace, close, _kind in loops:
            body = code[open_brace:close + 1]
            if re.search(r"\bfor\s+await\b", code[max(0, open_brace - 80):open_brace]):
                continue  # for await…of : itération volontaire d'un flux
            if not IO_IN_LOOP_RE.search(body):
                continue
            if self._inside_promise_all(code, open_brace, close):
                continue  # Promise.all(mapper) : requêtes parallèles, pas N+1
            line = _line_no(line_starts, open_brace)
            findings.append(self._f(
                sf, line, "perf-io-in-loop", "medium", "performance",
                "Entrée/sortie dans une boucle (N+1)",
                "Une requête réseau ou base de données est appelée à chaque "
                "itération (N+1) : les appels sont sérialisés.",
                "Grouper ou paralléliser les appels (Promise.all, batch).",
            ))

        # --- Boucle quadratique (O(n²)) ---------------------------------
        for open_brace, close, _kind in loops:
            body = code[open_brace:close + 1]
            nested = any(
                o > open_brace and c < close for (o, c, _) in loops
            )
            search = [
                mm for mm in LINEAR_SEARCH_RE.finditer(body)
                if not (raw and LITERAL_ARG_RE.match(raw, open_brace + mm.start()))
            ]
            if not (nested or search):
                continue
            line = _line_no(line_starts, open_brace)
            detail = "boucle imbriquée" if nested else \
                "recherche dans un tableau à l'intérieur d'une boucle"
            findings.append(self._f(
                sf, line, "perf-quadratic-loop", "medium", "performance",
                "Complexité quadratique (O(n²))",
                f"Complexité quadratique probable : {detail}.",
                "Indexer la collection interne dans un Map/Set (recherche O(1)).",
            ))

        # --- Débogage / alertes / clone JSON ----------------------------
        for rx, rid, sev, title, desc, rec in (
            (DEBUG_CONSOLE_RE, f"{prefix}-no-debug-console", "low",
             "Instruction de débogage",
             "Une instruction de débogage (console.log) est laissée dans le "
             "code de production.",
             "La retirer ou utiliser un logger conditionnel."),
            (ALERT_RE, f"{prefix}-no-alert", "low",
             "Boîte de dialogue bloquante",
             "alert()/confirm()/prompt() bloquent l'interface et trahissent "
             "souvent un oubli de débogage.",
             "Remplacer par un composant UI dédié."),
            (DEEP_CLONE_RE, f"{prefix}-deep-clone-json", "medium",
             "Copie profonde coûteuse",
             "JSON.parse(JSON.stringify(x)) copie lentement et perd les types.",
             "Utiliser structuredClone() ou une bibliothèque dédiée."),
        ):
            for m in rx.finditer(code):
                line = _line_no(line_starts, m.start())
                findings.append(self._f(
                    sf, line, rid, sev,
                    "performance" if rid.endswith("deep-clone-json") else "code_quality",
                    title, desc, rec,
                    snippet=self._snippet(line),
                ))

    # ------------------------------------------------------------------
    # Règles de blocs (JS/TS/PHP) : égalité lâche, catch vide, else-return…
    # ------------------------------------------------------------------
    def _brace_block_rules(self, findings, sf, code):
        prefix = self._prefix(sf)
        line_starts = _build_line_starts(code)

        # --- Égalité lâche (== / !=) -------------------------------------
        for m in LOOSE_EQ_RE.finditer(code):
            line = _line_no(line_starts, m.start())
            findings.append(self._f(
                sf, line, f"{prefix}-loose-equality", "low", "code_quality",
                "Égalité faible",
                "Égalité faible (== / !=) : la coercition de type est une "
                "source de bugs subtils.",
                "Utiliser === / !==.",
            ))

        # --- Booléens redondants -----------------------------------------
        for m in REDUNDANT_BOOL_RE.finditer(code):
            line = _line_no(line_starts, m.start())
            findings.append(self._f(
                sf, line, f"{prefix}-redundant-boolean", "low", "code_quality",
                "Littéral booléen redondant",
                "Comparaison ou affectation d'un littéral booléen redondante.",
                "Utiliser la condition directement (if (x), return cond).",
            ))

        # --- Catch vide ----------------------------------------------------
        pairs = self._brace_pairs(code)
        for start in sorted(pairs):
            pre = code[max(0, start - 60):start]
            if not re.search(r"\bcatch\s*\([^)]*\)\s*$", pre):
                continue
            body = code[start + 1:pairs[start]].strip()
            if body == "":
                line = _line_no(line_starts, start)
                findings.append(self._f(
                    sf, line, f"{prefix}-empty-catch", "medium", "code_quality",
                    "Bloc catch vide",
                    "Bloc catch vide : l'erreur est avalée silencieusement.",
                    "Journaliser l'erreur ou la relancer.",
                ))

        # --- else après un return ------------------------------------------
        close_to_open = {v: k for k, v in pairs.items()}
        for m in re.finditer(r"\belse\s*\{", code):
            pos = m.start()
            # Remonter les espaces/tabulations avant « else » jusqu'au `}`.
            j = pos
            while j > 0 and code[j - 1] in " \t\r\n":
                j -= 1
            if j == 0 or code[j - 1] != "}":
                continue
            close_brace = j - 1
            if close_brace not in close_to_open:
                continue
            block = code[close_to_open[close_brace] + 1:close_brace]
            tail = block.rstrip()
            if re.search(r"\b(?:return|break|continue|throw)\b[^;{}]*;?\s*$", tail):
                line = _line_no(line_starts, pos)
                findings.append(self._f(
                    sf, line, f"{prefix}-else-after-return", "medium",
                    "code_quality", "else après un return",
                    "Bloc else superflu : le if termine déjà par return/"
                    "break/continue/throw.",
                    "Dé-indenter le code qui suit pour réduire l'imbrication.",
                ))

        # --- Nombres magiques (conservateur) --------------------------------
        magic_seen = 0
        for m in re.finditer(
                r"(?<![.\w])(-?\d+)\s*(?:[<>]=?|===|==|!==|!=)\s*\w|"
                r"\w\s*(?:[<>]=?|===|==|!==|!=)\s*(-?\d+)(?![\w.])",
                code):
            number = m.group(1) or m.group(2)
            if number in MAGIC_SKIP:
                continue
            line = _line_no(line_starts, m.start())
            if self._line_declares_const(self._snippet(line)):
                continue
            findings.append(self._f(
                sf, line, f"{prefix}-magic-number", "low", "code_quality",
                "Nombre magique",
                f"Nombre magique dans une comparaison : {number}.",
                "L'extraire dans une constante nommée.",
            ))
            magic_seen += 1
            if magic_seen >= 2:
                break

    @staticmethod
    def _line_declares_const(line: str) -> bool:
        """True si la ligne déclare une constante nommée (const X = …)."""
        return bool(re.search(
            r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=", line
        ))
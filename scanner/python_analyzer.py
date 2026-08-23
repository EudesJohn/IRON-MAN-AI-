"""Analyseur statique Python basé sur le module natif `ast`.

C'est le cœur de CodeScan pour les fichiers Python. Chaque règle parcourt
l'arbre de syntaxe abstraite (AST) et émet des `Finding` :

  - py-dangerous-eval       : eval() / exec() sur données possiblement non fiables
  - py-pickle-load          : désérialisation non sûre (pickle, yaml.load, marshal)
  - py-bare-except          : `except:` nu qui masque les erreurs
  - py-subprocess-shell     : subprocess avec shell=True (injection de commandes)
  - py-sql-injection        : requête SQL construite par concaténation / f-string
  - py-assert-security      : assert utilisé comme contrôle de sécurité
  - py-dangerous-import     : import de modules dangereux (marshal, pickle…)
  - py-os-system            : appel à os.system / os.popen
  - py-hardcoded-secret     : variable nommée comme un secret = littéral en clair
  - py-long-function        : fonction trop longue (code quality)
  - py-high-complexity      : complexité cyclomatique excessive
  - py-cognitive-complexity : complexité cognitive élevée
  - py-deep-nesting         : imbrication excessive
  - py-too-many-params      : trop de paramètres
  - py-else-after-return    : else superflu après un return/raise
  - py-redundant-boolean    : comparaison booléenne redondante
  - py-empty-except         : except vide (pass) qui avale les erreurs

Les seuils des règles de qualité sont centralisés dans `scanner/thresholds.py`
(fonction > 50 lignes, cyclomatique > 10, cognitive > 15, imbrication > 4,
plus de 4 paramètres) — parité avec le rapport Herald.
"""

import ast
import re

from scanner.models import Finding
from scanner.thresholds import threshold

# Noms de variables considérés comme des indicateurs de secret.
SECRET_VAR_PATTERN = re.compile(
    r"(password|passwd|pwd|api[_-]?key|apikey|secret|token|"
    r"client[_-]?secret|access[_-]?key|auth[_-]?token)",
    re.IGNORECASE,
)

# Variables qui *décrivent* un secret plutôt que d'en contenir la valeur :
# `token_type = "bearer"`, `token_algorithm = "HS256"` (champs OAuth/JWT).
# Ces noms contiennent « token »/« secret » mais ne sont pas des secrets.
SECRET_TYPE_SUFFIX = re.compile(
    r"_(type|kind|scheme|algorithm|format)$", re.IGNORECASE
)

# Mots-clés SQL signalant une requête construite dynamiquement.
SQL_KEYWORDS = (
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "WHERE",
)

# Modules Python dont la (dé)sérialisation ou l'usage est dangereux.
DANGEROUS_MODULES = {"pickle", "cPickle", "marshal", "shelve", "telnetlib"}

# Fonctions d'attribut considérées comme de la désérialisation non sûre.
UNSAFE_DESERIALIZE = {"loads", "load", "load_all", "loads_from"}

# Fonctions de subprocess susceptibles d'invoquer un shell.
SUBPROCESS_FUNCS = {"call", "check_call", "check_output", "run", "Popen", "popen"}

# Mots-clés de sécurité pour les assertions (contrôles d'authentification…).
SECURITY_ASSERT_KEYWORDS = {
    "admin", "role", "permission", "authenticated", "authorized", "superuser",
    "is_admin", "login", "auth", "user_id", "owner", "token", "role_id",
}

# Fonctions HTTP du module `requests` (vérification timeout / TLS).
REQUESTS_FUNCS = {
    "get", "post", "put", "delete", "patch", "head", "options", "request",
}

# Fonctions de hachage faibles (ne pas utiliser pour des mots de passe/signatures).
WEAK_HASH_FUNCS = {"md5", "sha1"}

# Appels XML à risque d'XXE / bombe XML (le correctif est `defusedxml`).
XML_PARSE_RE = re.compile(
    r"(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|xml\.parsers\.expat|lxml(?:\.etree)?|ET|minidom)\s*\.\s*(?:fromstring|parse|iterparse|parseString|ParserCreate)\s*[(]"
)

# Noms de fonctions dédiés à la génération de jetons/clés (contexte
# « sécurité » pour la règle py-insecure-random).
SECURITY_FN_NAME = re.compile(
    r"(token|key|secret|password|passwd|pwd|otp|nonce|csrf|session|salt|"
    r"signature|credential|auth)", re.IGNORECASE
)

# Les seuils de qualité (longueur, cyclomatique, etc.) sont centralisés
# dans scanner/thresholds.py et lus via `threshold(...)` (parité Herald).


def _imports_defusedxml(tree) -> bool:
    """True si le module `defusedxml` est réellement importé dans l'arbre.

    On vérifie l'import AST (et non une sous-chaîne du contenu) : un
    commentaire mentionnant « defusedxml » (ex. la recommandation du
    correctif) ne doit pas désactiver la règle.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(n.name == "defusedxml" or n.name.startswith("defusedxml.")
                   for n in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "defusedxml"
                                or node.module.startswith("defusedxml.")):
                return True
    return False


def _finding(file, line, rule_id, severity, category, title, description,
             recommendation, snippet="", col=0):
    """Fabrique un Finding standard pour l'analyseur Python."""
    return Finding(
        file=file, line=line, column=col, rule_id=rule_id, category=category,
        severity=severity, title=title, description=description,
        recommendation=recommendation, snippet=snippet.strip(),
        language="python", source="python_analyzer",
    )


class PythonAnalyzer:
    """Analyse un fichier Python en le parsant avec `ast`."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------
    def analyze(self, sf, content: str) -> list:
        """Analyse le contenu d'un fichier Python et renvoie les findings."""
        findings = []
        try:
            tree = ast.parse(content, filename=sf.relpath)
        except SyntaxError as exc:
            if self.verbose:
                print(f"  [python] {sf.relpath} : erreur de syntaxe (ligne {exc.lineno})")
            return findings

        lines = content.splitlines()

        # Carte des parents (pour remonter jusqu'au contexte d'un appel :
        # fonction englobante, cible d'affectation…).
        parents = {
            id(child): node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        has_defusedxml = _imports_defusedxml(tree)

        for node in ast.walk(tree):
            findings.extend(self._check_call(node, sf, lines))
            findings.extend(self._check_requests_http(node, sf, lines))
            findings.extend(self._check_weak_hash(node, sf, lines))
            findings.extend(self._check_insecure_random(node, sf, lines, parents))
            findings.extend(self._check_tempfile_mktemp(node, sf, lines))
            findings.extend(self._check_assign_secret(node, sf, lines))
            findings.extend(self._check_bare_except(node, sf, lines))
            findings.extend(self._check_sql(node, sf, lines))
            findings.extend(self._check_assert(node, sf, lines))
            findings.extend(self._check_import(node, sf, lines))
            findings.extend(self._check_complexity(node, sf, lines))
            findings.extend(self._check_else_after_return(node, sf, lines))
            findings.extend(self._check_redundant_boolean(node, sf, lines))
            findings.extend(self._check_empty_except(node, sf, lines))

        # Règle au niveau du contenu (parsing XML sans defusedxml).
        findings.extend(self._check_xml_usage(content, sf, lines, has_defusedxml))

        return findings

    # ------------------------------------------------------------------
    # Règles
    # ------------------------------------------------------------------
    def _check_call(self, node, sf, lines):
        """eval/exec, pickle/yaml/marshal.loads, subprocess shell, os.system."""
        if not isinstance(node, ast.Call):
            return []

        f = node.func

        # --- eval() / exec() -----------------------------------------
        if isinstance(f, ast.Name) and f.id in ("eval", "exec"):
            func_name = f.id
            # Sévérité critique si l'argument vient directement d'input()
            severity = "critical" if self._arg_is_user_input(node) else "high"
            desc = (
                f"{func_name}() exécute du code arbitraire. Passer une donnée "
                "non fiable à cette fonction équivaut à une exécution de code "
                "à distance (RCE)."
            )
            rec = ("Ne jamais exécuter de code dynamique avec des entrées "
                   "non fiables. Utiliser des parsers dédiés ou des "
                   "whitelists.")
            return [_finding(
                sf.relpath, node.lineno, "py-dangerous-eval", severity,
                "security_misc", f"Exécution de code dynamique ({func_name})",
                desc, rec,
                snippet=self._snippet(lines, node.lineno),
            )]

        # --- pickle / yaml / marshal : désérialisation non sûre -------
        if isinstance(f, ast.Attribute) and f.attr in UNSAFE_DESERIALIZE:
            obj = f.value
            mod = obj.id if isinstance(obj, ast.Name) else None
            # yaml.load est dangereux (yaml.safe_load est sûr) ;
            # pickle/marshal/shelve le sont toujours.
            if mod in DANGEROUS_MODULES or (mod == "yaml" and f.attr == "load"):
                name = mod
                desc = (f"{name}.{f.attr}() désérialise des données qui peuvent "
                        f"être non fiables. Cela peut exécuter du code arbitraire "
                        f"(règles de sécurité du format {name}).")
                rec = ("Utiliser un format sûr (JSON) ou limiter les classes "
                       "autorisées ; ne jamais désérialiser de données non "
                       "fiables avec pickle/marshal/yaml.load.")
                return [_finding(
                    sf.relpath, node.lineno, "py-pickle-load", "high",
                    "security_misc", f"Désérialisation non sûre ({name}.{f.attr})",
                    desc, rec, snippet=self._snippet(lines, node.lineno),
                )]

        # --- subprocess avec shell=True -------------------------------
        if (
            isinstance(f, ast.Attribute)
            and f.attr in SUBPROCESS_FUNCS
            and isinstance(f.value, ast.Name)
            and f.value.id == "subprocess"
        ):
            shell_node = self._kwarg(node, "shell")
            if shell_node is not None and self._is_true(shell_node):
                desc = ("subprocess avec shell=True invoque le shell système. "
                        "Une entrée utilisateur non échappée dans la commande "
                        "provoque une injection de commandes.")
                rec = ("Utiliser subprocess sans shell (liste d'arguments) "
                       "et désactiver shell=True.")
                return [_finding(
                    sf.relpath, node.lineno, "py-subprocess-shell", "high",
                    "injection", "subprocess avec shell=True",
                    desc, rec, snippet=self._snippet(lines, node.lineno),
                )]

        # --- os.system / os.popen -------------------------------------
        if (
            isinstance(f, ast.Attribute)
            and f.attr in ("system", "popen")
            and isinstance(f.value, ast.Name)
            and f.value.id == "os"
        ):
            desc = f"os.{f.attr}() exécute une commande via le shell système."
            rec = "Utiliser subprocess.run avec une liste d'arguments, sans shell."
            return [_finding(
                sf.relpath, node.lineno, "py-os-system", "high", "injection",
                f"Commande système (os.{f.attr})",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]

        return []

    def _check_requests_http(self, node, sf, lines):
        """requests.* : appel sans timeout (DoS) ou verify=False (TLS désactivé)."""
        if not isinstance(node, ast.Call):
            return []
        f = node.func
        if not (isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "requests"
                and f.attr in REQUESTS_FUNCS):
            return []

        out = []
        if self._kwarg(node, "timeout") is None:
            desc = (f"requests.{f.attr}() est appelé sans timeout : en cas de "
                    "réponse lente ou de serveur muet, le worker HTTP reste "
                    "bloqué indéfiniment (épuisement des threads, DoS).")
            rec = ("Toujours passer un timeout explicite, par ex. "
                   "requests.get(url, timeout=10).")
            out.append(_finding(
                sf.relpath, node.lineno, "py-request-without-timeout", "medium",
                "security_misc", "Requête HTTP sans timeout",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            ))

        verify = self._kwarg(node, "verify")
        if verify is not None and self._is_false(verify):
            desc = (f"requests.{f.attr}() est appelé avec verify=False : la "
                    "vérification du certificat TLS est désactivée. La "
                    "connexion devient vulnérable à l'interception (homme "
                    "du milieu).")
            rec = ("Ne jamais désactiver la vérification TLS ; si le "
                   "certificat pose problème, corriger la chaîne de "
                   "confiance ou utiliser un CA personnalisé (verify=chemin).")
            out.append(_finding(
                sf.relpath, node.lineno, "py-verify-false", "high",
                "security_misc", "Vérification TLS désactivée (verify=False)",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            ))
        return out

    def _check_weak_hash(self, node, sf, lines):
        """hashlib.md5/sha1 (ou hashlib.new('md5')) : hachage faible."""
        if not isinstance(node, ast.Call):
            return []
        f = node.func
        hit = False
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                and f.value.id == "hashlib" and f.attr in WEAK_HASH_FUNCS:
            hit = f.attr
        elif (isinstance(f, ast.Attribute) and f.attr == "new"
              and isinstance(f.value, ast.Name) and f.value.id == "hashlib"
              and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)
              and node.args[0].value.lower() in WEAK_HASH_FUNCS):
            hit = node.args[0].value.lower()
        if not hit:
            return []
        desc = (f"Le hachage {hit}() est cryptographiquement faible (collisions "
                "connues) : inadapté aux mots de passe, signatures ou "
                "vérifications d'intégrité sensibles.")
        rec = ("Utiliser un algorithme fort (sha256+, bcrypt/argon2 pour les "
               "mots de passe, HMAC avec clé pour les signatures).")
        return [_finding(
            sf.relpath, node.lineno, "py-weak-hash", "medium",
            "security_misc", f"Fonction de hachage faible ({hit})",
            desc, rec, snippet=self._snippet(lines, node.lineno),
        )]

    def _check_insecure_random(self, node, sf, lines, parents):
        """`random.*` utilisé pour générer un secret/jeton (préférer `secrets`)."""
        if not isinstance(node, ast.Call):
            return []
        f = node.func
        if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id == "random"):
            return []

        # Contexte « sécurité » : la valeur est affectée à une variable nommée
        # comme un secret, ou la fonction englobante génère des jetons/clés.
        target = self._assign_target_name(node, parents)
        func_name = self._enclosing_function_name(node, parents)
        if not ((target and SECRET_VAR_PATTERN.search(target))
                or (func_name and SECURITY_FN_NAME.search(func_name))):
            return []

        desc = ("Le module `random` (PRNG non cryptographique) est utilisé "
                "pour produire une valeur sensible : ses sorties sont "
                "prévisibles et ne doivent jamais servir à des jetons, "
                "mots de passe ou nonces.")
        rec = ("Utiliser le module `secrets` (secrets.token_hex, "
               "secrets.choice…) conçu pour la cryptographie.")
        return [_finding(
            sf.relpath, node.lineno, "py-insecure-random", "medium",
            "security_misc", "Générateur aléatoire non sûr (random)",
            desc, rec, snippet=self._snippet(lines, node.lineno),
        )]

    def _check_tempfile_mktemp(self, node, sf, lines):
        """tempfile.mktemp() : fichier temporaire prévisible (course)."""
        if not isinstance(node, ast.Call):
            return []
        f = node.func
        if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id == "tempfile" and f.attr == "mktemp"):
            return []
        desc = ("tempfile.mktemp() crée un nom de fichier prévisible puis le "
                "libère : un attaquant peut deviner le chemin et créer un "
                "lien symbolique avant l'ouverture (course, écriture "
                "arbitraire).")
        rec = ("Utiliser tempfile.NamedTemporaryFile / tempfile.mkstemp "
               "qui créent le fichier de façon atomique.")
        return [_finding(
            sf.relpath, node.lineno, "py-tempfile-mktemp", "medium",
            "security_misc", "Fichier temporaire prévisible (mktemp)",
            desc, rec, snippet=self._snippet(lines, node.lineno),
        )]

    def _check_xml_usage(self, content, sf, lines, has_defusedxml):
        """Parsing XML sans defusedxml : risque d'XXE / bombe XML."""
        if has_defusedxml:
            return []
        out = []
        for m in XML_PARSE_RE.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            desc = ("Parsing XML avec une bibliothèque standard (ou lxml) "
                    "sans protection : les entités externes et les bombes "
                    "d'expansion peuvent être exploitées (XXE, lecture de "
                    "fichiers, déni de service).")
            rec = ("Utiliser defusedxml (defusedxml.ElementTree, "
                   "defusedxml.minidom…) ou désactiver explicitement la "
                   "résolution d'entités externes.")
            out.append(_finding(
                sf.relpath, line, "py-xml-unsafe", "high", "security_misc",
                "Parsing XML non sûr (risque XXE)",
                desc, rec, snippet=self._snippet(lines, line),
            ))
        return out

    def _check_assign_secret(self, node, sf, lines):
        """`password = "…"` : secret codé en dur dans une variable nommée."""
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            return []

        if value is None:
            return []

        # Valeur littérale de chaîne uniquement (longueur significative).
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return []
        secret_value = value.value
        if len(secret_value) < 4:
            return []

        for target in targets:
            name = self._target_name(target)
            if name and SECRET_VAR_PATTERN.search(name):
                # `token_type = "bearer"` décrit la nature d'un jeton (pas une
                # valeur secrète) : on l'ignore si la valeur est courte.
                if SECRET_TYPE_SUFFIX.search(name) and len(secret_value) < 16:
                    continue
                desc = (f"Le secret « {name} » est codé en dur dans le code "
                        f"(valeur : « {secret_value} »). Il est visible par "
                        "toute personne ayant accès au dépôt.")
                rec = ("Déplacer le secret dans une variable d'environnement "
                       "ou un gestionnaire de secrets, puis le révoquer.")
                return [_finding(
                    sf.relpath, node.lineno, "py-hardcoded-secret", "high",
                    "secrets", f"Secret codé en dur ({name})",
                    desc, rec, snippet=self._snippet(lines, node.lineno),
                )]
        return []

    def _check_bare_except(self, node, sf, lines):
        """`except:` nu : masque silencieusement toutes les erreurs."""
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            desc = ("Un except sans type capture toutes les exceptions et "
                    "peut masquer des erreurs réelles (dont des attaques).")
            rec = ("Préciser les exceptions attendues, par ex. "
                   "except ValueError: ou except OSError as exc:.")
            return [_finding(
                sf.relpath, node.lineno, "py-bare-except", "medium",
                "security_misc", "Bloc except nu",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]
        return []

    def _check_sql(self, node, sf, lines):
        """Requête SQL construite dynamiquement (concat / f-string / %)."""
        text, dynamic = self._collect_sql_parts(node)
        if not dynamic or not text:
            return []
        if any(kw in text.upper() for kw in SQL_KEYWORDS):
            desc = ("Une requête SQL est construite par concaténation de "
                    "chaînes ou f-string avec des variables non échappées : "
                    "risque d'injection SQL.")
            rec = ("Utiliser des requêtes paramétrées (placeholders ? ou %s) "
                   "via sqlite3, psycopg2 ou un ORM.")
            return [_finding(
                sf.relpath, node.lineno, "py-sql-injection", "high",
                "injection", "Injection SQL possible (requête dynamique)",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]
        return []

    def _check_assert(self, node, sf, lines):
        """assert utilisé comme contrôle de sécurité (désactivé en mode -O)."""
        if not isinstance(node, ast.Assert):
            return []
        names = {
            n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)
        }
        # Les attributs (ex. `user.is_admin`) sont des chaînes, pas des nœuds
        # Name : on les collecte aussi.
        names |= {
            a.attr for a in ast.walk(node.test) if isinstance(a, ast.Attribute)
        }
        # Intersection mot-à-mot sur les identifiants de la condition.
        security_hint = bool(names & SECURITY_ASSERT_KEYWORDS)
        # Recherche en sous-chaîne dans le message d'assertion éventuel
        # (permet de détecter des libellés comme « administrateur »).
        if isinstance(node.msg, ast.Constant) and isinstance(node.msg.value, str):
            msg = node.msg.value.lower()
            security_hint = security_hint or any(
                k in msg for k in SECURITY_ASSERT_KEYWORDS
            )
        if security_hint:
            desc = ("Cette assertion semble contrôler un privilège ou une "
                    "authentification. Les assertions sont supprimées lorsque "
                    "Python est lancé avec -O / -OO : le contrôle sauterait "
                    "en production.")
            rec = ("Remplacer l'assertion par une vérification explicite "
                   "(if … : raise PermissionError) qui reste active en mode "
                   "optimisé.")
            return [_finding(
                sf.relpath, node.lineno, "py-assert-security", "medium",
                "security_misc", "Assertion utilisée pour un contrôle de sécurité",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]
        return []

    def _check_import(self, node, sf, lines):
        """Import de modules dangereux (marshal, pickle, shelve…)."""
        module = None
        if isinstance(node, ast.Import):
            module = node.names[0].name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
        if not module:
            return []
        top = module.split(".")[0]
        if top in DANGEROUS_MODULES:
            desc = f"Le module « {top} » est à l'origine de désérialisations non sûres."
            rec = "Éviter d'importer ce module ; préférer json ou une librairie sûre."
            return [_finding(
                sf.relpath, node.lineno, "py-dangerous-import", "medium",
                "security_misc", f"Import de module dangereux ({top})",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]
        return []

    def _check_complexity(self, node, sf, lines):
        """Métriques de fonction : longueur, cyclomatique, cognitive,
        imbrication, paramètres (seuils centralisés dans thresholds.py)."""
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
        length = end_line - node.lineno + 1

        out = []
        fn_limit = threshold("function_lines")
        if length > fn_limit:
            out.append(_finding(
                sf.relpath, node.lineno, "py-long-function", "low",
                "code_quality", f"Fonction trop longue ({node.name})",
                f"La fonction « {node.name} » fait {length} lignes "
                f"(seuil : {fn_limit}).",
                "Découper la fonction en sous-fonctions plus petites.",
                snippet=self._snippet(lines, node.lineno),
            ))

        cc_limit = threshold("cyclomatic_complexity")
        complexity = self._cyclomatic(node)
        if complexity > cc_limit:
            out.append(_finding(
                sf.relpath, node.lineno, "py-high-complexity", "medium",
                "code_quality", f"Complexité cyclomatique excessive ({node.name})",
                f"La complexité cyclomatique de « {node.name} » est de "
                f"{complexity} (seuil : {cc_limit}).",
                "Simplifier la logique et extraire les branches conditionnelles.",
                snippet=self._snippet(lines, node.lineno),
            ))

        cognitive = self._cognitive(node)
        co_limit = threshold("cognitive_complexity")
        if cognitive > co_limit:
            out.append(_finding(
                sf.relpath, node.lineno, "py-cognitive-complexity", "medium",
                "code_quality", f"Complexité cognitive élevée ({node.name})",
                f"La complexité cognitive de « {node.name} » est de "
                f"{cognitive} (seuil : {co_limit}).",
                "Aplatir l'imbrication avec des clauses de garde (early returns).",
                snippet=self._snippet(lines, node.lineno),
            ))

        depth = self._max_nesting(node)
        nest_limit = threshold("nesting_depth")
        if depth > nest_limit:
            out.append(_finding(
                sf.relpath, node.lineno, "py-deep-nesting", "medium",
                "code_quality", f"Imbrication excessive ({node.name})",
                f"L'imbrication de « {node.name} » atteint {depth} niveaux "
                f"(limite : {nest_limit}).",
                "Utiliser des retours anticipés ou extraire des fonctions.",
                snippet=self._snippet(lines, node.lineno),
            ))

        n_params = self._count_params(node)
        param_limit = threshold("max_params")
        if n_params > param_limit:
            out.append(_finding(
                sf.relpath, node.lineno, "py-too-many-params", "medium",
                "code_quality", f"Trop de paramètres ({node.name})",
                f"« {node.name} » prend {n_params} paramètres "
                f"(seuil : {param_limit}).",
                "Regrouper les arguments liés dans un objet/struct.",
            ))

        return out

    def _check_else_after_return(self, node, sf, lines):
        """`else` superflu : le `if` termine déjà par return/raise."""
        if not isinstance(node, ast.If):
            return []
        if not node.orelse:
            return []
        if node.orelse and isinstance(node.orelse[-1], ast.If):
            return []  # chaîne elif : pas un else final
        last = node.body[-1] if node.body else None
        if not self._is_terminal(last):
            return []
        desc = ("Le bloc if se termine par return/raise : le else qui suit "
                "est superflu (code mort pour cette branche).")
        rec = ("Dé-indenter le code du bloc else pour réduire l'imbrication.")
        return [_finding(
            sf.relpath, node.lineno, "py-else-after-return", "medium",
            "code_quality", "else superflu après un return",
            desc, rec, snippet=self._snippet(lines, node.lineno),
        )]

    def _check_redundant_boolean(self, node, sf, lines):
        """Comparaisons redondantes avec un littéral booléen (x == True…)."""
        if not isinstance(node, ast.Compare):
            return []
        for op, cpt in zip(node.ops, node.comparators):
            is_bool_left = (isinstance(node.left, ast.Constant)
                            and isinstance(node.left.value, bool))
            is_bool_right = (isinstance(cpt, ast.Constant)
                             and isinstance(cpt.value, bool))
            if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) \
                    and (is_bool_left or is_bool_right):
                desc = ("Comparaison d'une condition avec un littéral booléen "
                        "redondante : `x == True`/`x is False` fausse le sens.")
                rec = ("Écrire la condition directement (`if x:` ou `if not x:`) "
                       "pour du code plus lisible.")
                return [_finding(
                    sf.relpath, node.lineno, "py-redundant-boolean", "low",
                    "code_quality", "Comparaison booléenne redondante",
                    desc, rec, snippet=self._snippet(lines, node.lineno),
                )]
        return []

    def _check_empty_except(self, node, sf, lines):
        """`except … : pass` : erreurs avalées silencieusement."""
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            return []
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            desc = ("Un bloc except ne contient que `pass` : l'erreur est "
                    "avalée sans aucune trace ni action.")
            rec = ("Au minimum journaliser l'erreur (logging.exception), ou "
                   "restreindre le type d'exception attendu.")
            return [_finding(
                sf.relpath, node.lineno, "py-empty-except", "medium",
                "code_quality", "Exception avalée (except: pass)",
                desc, rec, snippet=self._snippet(lines, node.lineno),
            )]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _snippet(lines, lineno, width=140):
        """Extrait la ligne concernée du fichier source (pour le rapport)."""
        if 0 < lineno <= len(lines):
            return lines[lineno - 1][:width]
        return ""

    @staticmethod
    def _arg_is_user_input(node) -> bool:
        """True si un argument d'un appel provient de input()."""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                f = arg.func
                if isinstance(f, ast.Name) and f.id == "input":
                    return True
        return False

    @staticmethod
    def _kwarg(node, name):
        """Renvoie le noeud valeur du keyword `name`, ou None."""
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _is_true(node) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def _is_false(node) -> bool:
        return isinstance(node, ast.Constant) and node.value is False

    @staticmethod
    def _ancestors(node, parents):
        """Remonte la chaîne des ancêtres de `node` via la carte parents."""
        cur = node
        while id(cur) in parents:
            cur = parents[id(cur)]
            yield cur

    def _assign_target_name(self, node, parents) -> str:
        """Nom de la variable cible de l'affectation englobante (si affectation)."""
        for anc in self._ancestors(node, parents):
            if isinstance(anc, ast.Assign):
                for target in anc.targets:
                    name = self._target_name(target)
                    if name:
                        return name
                return ""
            if isinstance(anc, ast.AnnAssign):
                return self._target_name(anc.target)
        return ""

    def _enclosing_function_name(self, node, parents) -> str:
        """Nom de la fonction (ou méthode) englobante la plus proche."""
        for anc in self._ancestors(node, parents):
            if isinstance(anc, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return anc.name
        return ""

    @staticmethod
    def _target_name(target) -> str:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return ""

    @classmethod
    def _collect_sql_parts(cls, node):
        """Analyse un noeud pour y déceler une chaîne SQL dynamique.

        Renvoie (texte_assemblé, contient_une_partie_dynamique).
        """
        # f-string : "SELECT … {var} …"
        if isinstance(node, ast.JoinedStr):
            parts = []
            dynamic = False
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    dynamic = True
                    parts.append("{}")
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
            return "".join(parts), dynamic

        # Concaténation : "SELECT …" + var + " …"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, left_dyn = cls._collect_sql_parts(node.left)
            right, right_dyn = cls._collect_sql_parts(node.right)
            return left + right, (left_dyn or right_dyn)

        # Formatage : "SELECT … %s" % var
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left, _ = cls._collect_sql_parts(node.left)
            return left, True

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, False
        # N'importe quelle autre expression : considérée comme dynamique.
        return "", True

    @staticmethod
    def _cyclomatic(func) -> int:
        """Calcule la complexité cyclomatique d'une fonction (base = 1)."""
        complexity = 1
        for child in ast.walk(func):
            # On ignore les fonctions imbriquées (elles seront évaluées seules).
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) \
                    and child is not func:
                continue
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor,
                                  ast.ExceptHandler, ast.IfExp, ast.Assert,
                                  ast.Match)):
                complexity += 1
            elif isinstance(child, ast.BoolOp) and isinstance(child.op,
                                                              (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(child, ast.With) and getattr(child, "is_async", False):
                complexity += 1
        return complexity

    @staticmethod
    def _is_decision(node) -> bool:
        """True si le nœud ouvre un (ou plusieurs) chemin de décision."""
        if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor,
                             ast.ExceptHandler, ast.IfExp, ast.Assert,
                             ast.Match, ast.With)):
            return True
        return isinstance(node, ast.BoolOp) and isinstance(node.op,
                                                           (ast.And, ast.Or))

    def _cognitive(self, func) -> int:
        """Complexité cognitive approximative : Σ (1 + profondeur) (Sonar)."""
        parents = {
            id(child): node
            for node in ast.walk(func)
            for child in ast.iter_child_nodes(node)
        }
        total = 0
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.Lambda)) and node is not func:
                continue
            if not self._is_decision(node):
                continue
            depth = 0
            cur = node
            while cur is not func and id(cur) in parents:
                cur = parents[id(cur)]
                if self._is_decision(cur):
                    depth += 1
            total += 1 + depth
        return total

    @staticmethod
    def _max_nesting(func) -> int:
        """Profondeur maximale d'imbrication des blocs de contrôle."""
        best = 0

        def walk(node, depth):
            nonlocal best
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.Lambda)):
                    continue  # fonctions imbriquées évaluées séparément
                if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor,
                                      ast.ExceptHandler, ast.Try, ast.Match,
                                      ast.With)):
                    if depth + 1 > best:
                        best = depth + 1
                    walk(child, depth + 1)
                else:
                    walk(child, depth)
        walk(func, 0)
        return best

    @staticmethod
    def _count_params(func) -> int:
        """Nombre de paramètres (positionnels + keywords) d'une fonction."""
        return len(func.args.args) + len(func.args.kwonlyargs)

    @staticmethod
    def _is_terminal(stmt) -> bool:
        """True si le nœud est une instruction de sortie de contrôle."""
        return isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))

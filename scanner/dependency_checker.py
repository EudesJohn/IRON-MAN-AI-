"""Vérification des dépendances contre la base de vulnérabilités OSV.dev.

Ce module :
  1. parse les manifestes de dépendances (requirements.txt, package.json,
     composer.json, Gemfile, go.mod…) ;
  2. interroge l'API publique et gratuite OSV.dev (https://osv.dev) en
     mode batch ;
  3. transforme chaque CVE remontée en `Finding` avec une sévérité
     calculée depuis le score CVSS ou le niveau fourni par OSV.

Aucune API d'IA n'est utilisée : OSV.dev est simplement une base de
données de vulnérabilités connues (comme NVD/GHSA).
"""

import json
import math
import re

from scanner.crawler import read_text_file
from scanner.models import Finding

# Endpoints de l'API publique OSV.dev.
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Correspondance manifeste -> écosystème OSV.
ECOSYSTEM_BY_MANIFEST = {
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "package.json": "npm",
    "composer.json": "Packagist",
    "Gemfile": "RubyGems",
    "go.mod": "Go",
}

# Taille maximale d'un lot de requêtes envoyées à OSV.
BATCH_SIZE = 100


class DependencyChecker:
    """Vérifie les dépendances d'un projet contre OSV.dev."""

    def __init__(self, offline: bool = False, verbose: bool = False,
                 timeout: int = 30):
        self.offline = offline        # --no-deps : désactive le réseau
        self.verbose = verbose
        self.timeout = timeout
        self._session = None          # lazy import de requests

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------
    def analyze(self, manifest_files: list) -> list:
        """Analyse les manifestes et renvoie les findings de CVE."""
        if self.offline:
            if self.verbose:
                print("[deps] Vérification OSV.dev désactivée (--no-deps).")
            return []

        deps = []
        for sf in manifest_files:
            try:
                deps.extend(self._parse_manifest(sf))
            except (OSError, json.JSONDecodeError) as exc:
                if self.verbose:
                    print(f"[deps] Manifeste illisible {sf.relpath} : {exc}")

        if not deps:
            return []
        if self.verbose:
            print(f"[deps] {len(deps)} dépendances à vérifier sur OSV.dev")

        return self._query_osv(deps)

    # ------------------------------------------------------------------
    # Parsing des manifestes
    # ------------------------------------------------------------------
    def _parse_manifest(self, sf) -> list:
        """Parse un manifeste et renvoie [{package, version, ecosystem, manifest, line}]."""
        content = read_text_file(sf.path)
        name = sf.relpath.split("/")[-1].lower()

        if is_requirements_like(name):
            return self._parse_requirements(content, sf.relpath)
        if name == "package.json":
            return self._parse_package_json(content, sf.relpath)
        if name == "composer.json":
            return self._parse_composer_json(content, sf.relpath)
        if name in ("Gemfile", "Gemfile.lock"):
            return self._parse_gemfile(content, sf.relpath)
        if name == "go.mod":
            return self._parse_go_mod(content, sf.relpath)
        if name == "pipfile":
            return self._parse_pipfile(content, sf.relpath)
        if name == "cargo.toml":
            return self._parse_cargo_toml(content, sf.relpath)
        if name == "pom.xml":
            return self._parse_pom_xml(content, sf.relpath)
        return []

    @staticmethod
    def _parse_requirements(content, manifest):
        deps = []
        # `(?:\[[^\]]*\])?` absorbe les extras (ex. `uvicorn[standard]`) pour
        # que la version soit bien prise en compte dans la requête OSV.
        # Sans cela, `uvicorn[standard]==0.30.0` serait traité comme non
        # versionné et OSV renverrait TOUTES les CVE du paquet (bruit).
        pattern = re.compile(
            r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;]+)"
        )
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            # Lignes non versionnées : -e, -r, URLs, git…
            if line.startswith(("-e ", "--index", "-r ", "-c ", "http:", "https:",
                               "git+", "git://", "file:")):
                continue
            m = pattern.match(line)
            if m:
                pkg, op, ver = m.group(1), m.group(2), m.group(3)
                # Version exacte (==) : requête précise.
                # Plage (>=, >, ~=) : on interroge la version minimale
                # autorisée — les CVE affectant cette version sont
                # pertinentes pour toute version installée de la plage.
                # Bornes hautes (<=, <, !=) : version inconnue -> sans version.
                query_version = None
                if op == "==" or op == "~=":
                    query_version = ver
                elif op in (">=", ">"):
                    query_version = ver.split(",")[0]
                deps.append({
                    "package": pkg.lower(),
                    "version": query_version,
                    "ecosystem": "PyPI",
                    "manifest": manifest,
                    "line": lineno,
                    "constraint": raw,
                })
            else:
                # Dépendance sans version (ex. `flask` seul) ;
                # on retire les extras éventuels : `requests[security]` -> `requests`.
                pkg = re.split(r"\[", line)[0].strip()
                deps.append({
                    "package": pkg.lower().replace(" ", ""),
                    "version": None,
                    "ecosystem": "PyPI",
                    "manifest": manifest,
                    "line": lineno,
                    "constraint": raw,
                })
        return deps

    @staticmethod
    def _parse_package_json(content, manifest):
        deps = []
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in (data.get(section) or {}).items():
                deps.append({
                    "package": pkg,
                    "version": _normalize_version(ver),
                    "ecosystem": "npm",
                    "manifest": manifest,
                    "line": _find_json_line(content, pkg),
                    "constraint": ver,
                })
        return deps

    @staticmethod
    def _parse_composer_json(content, manifest):
        deps = []
        data = json.loads(content)
        for section in ("require", "require-dev"):
            for pkg, ver in (data.get(section) or {}).items():
                # On ignore les contraintes liées à la plateforme (php, ext-*)
                if pkg == "php" or pkg.startswith("ext-") or pkg.startswith("lib-"):
                    continue
                deps.append({
                    "package": pkg,
                    "version": _normalize_version(ver),
                    "ecosystem": "Packagist",
                    "manifest": manifest,
                    "line": _find_json_line(content, pkg),
                    "constraint": ver,
                })
        return deps

    @staticmethod
    def _parse_gemfile(content, manifest):
        deps = []
        pattern = re.compile(r'^\s*gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?')
        for lineno, raw in enumerate(content.splitlines(), start=1):
            m = pattern.match(raw)
            if not m:
                continue
            pkg, ver = m.group(1), m.group(2)
            deps.append({
                "package": pkg,
                "version": _normalize_version(ver) if ver else None,
                "ecosystem": "RubyGems",
                "manifest": manifest,
                "line": lineno,
                "constraint": ver or "*",
            })
        return deps

    @staticmethod
    def _parse_go_mod(content, manifest):
        deps = []
        pattern = re.compile(r"^\s*([^\s]+)\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)")
        in_require = False
        for lineno, raw in enumerate(content.splitlines(), start=1):
            stripped = raw.strip()
            if stripped == "require (":
                in_require = True
                continue
            if stripped == ")":
                in_require = False
                continue
            m = pattern.match(raw)
            if m and (in_require or stripped.startswith("require ")):
                deps.append({
                    "package": m.group(1),
                    "version": m.group(2),
                    "ecosystem": "Go",
                    "manifest": manifest,
                    "line": lineno,
                    "constraint": m.group(2),
                })
        return deps

    @staticmethod
    def _parse_pipfile(content, manifest):
        """Pipfile : sections [packages] / [dev-packages], `name = "==x.y.z"`."""
        deps = []
        section = None
        for lineno, raw in enumerate(content.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
                continue
            if section not in ("packages", "dev-packages"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*=\s*(.+)", stripped)
            if not m:
                continue
            pkg, spec = m.group(1), m.group(2).strip()
            version = None
            m2 = re.search(r'["\']([\^~=<>!]*\s*\d[\w.\-]*)["\']', spec)
            if m2:
                version = _normalize_version(m2.group(1))
            deps.append({
                "package": pkg.lower(),
                "version": version,
                "ecosystem": "PyPI",
                "manifest": manifest,
                "line": lineno,
                "constraint": spec,
            })
        return deps

    @staticmethod
    def _parse_cargo_toml(content, manifest):
        """Cargo.toml : `name = \"1.2.3\"` ou `name = { version = \"1.2.3\" }`."""
        deps = []
        section = None
        for lineno, raw in enumerate(content.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
                continue
            if section not in ("dependencies", "dev-dependencies"):
                continue
            m = re.match(r"([A-Za-z0-9_\-]+)\s*=\s*(.+)", stripped)
            if not m:
                continue
            pkg, spec = m.group(1), m.group(2).strip()
            version = None
            m2 = re.search(r'["\']([\^~=<>!]*\s*\d[\w.\-]*)["\']', spec)
            if m2:
                version = _normalize_version(m2.group(1))
            # Dépendance git/path sans version : non interrogée.
            if version is None and spec.startswith("{"):
                continue
            deps.append({
                "package": pkg,
                "version": version,
                "ecosystem": "crates.io",
                "manifest": manifest,
                "line": lineno,
                "constraint": spec,
            })
        return deps

    @staticmethod
    def _parse_pom_xml(content, manifest):
        """pom.xml : blocs <dependency> avec <artifactId> et <version>."""
        deps = []
        for m in re.finditer(r"<dependency>\s*(.*?)\s*</dependency>",
                             content, re.DOTALL):
            block = m.group(1)
            am = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
            if not am:
                continue
            pkg = am.group(1).strip()
            vm = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
            version = None
            if vm and re.match(r"^[\w.\-]+$", vm.group(1).strip()):
                version = _normalize_version(vm.group(1).strip())
            if not version:
                continue  # version héritée (parent) : non résolvable ici
            line = content.count("\n", 0, am.start()) + 1
            deps.append({
                "package": pkg,
                "version": version,
                "ecosystem": "Maven",
                "manifest": manifest,
                "line": line,
                "constraint": vm.group(1).strip(),
            })
        return deps

    # ------------------------------------------------------------------
    # Interrogation d'OSV.dev
    # ------------------------------------------------------------------
    def _query_osv(self, deps: list) -> list:
        """Interroge OSV.dev (batch) et renvoie les findings CVE."""
        try:
            import requests
        except ImportError:
            print("[deps] Le module `requests` est requis pour OSV.dev "
                  "(pip install requests).")
            return []

        findings = []
        batches = [deps[i:i + BATCH_SIZE] for i in range(0, len(deps), BATCH_SIZE)]

        for batch in batches:
            payload = {
                "queries": [
                    {"package": {"name": d["package"], "ecosystem": d["ecosystem"]}}
                    if d["version"] is None else
                    {"package": {"name": d["package"], "ecosystem": d["ecosystem"]},
                     "version": d["version"]}
                    for d in batch
                ]
            }
            try:
                resp = requests.post(OSV_BATCH_URL, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                results = resp.json().get("results", [])
            except Exception as exc:
                print(f"[deps] OSV.dev indisponible ({exc}) — "
                      "vérification des dépendances ignorée.")
                return findings

            for dep, result in zip(batch, results):
                vulns = (result or {}).get("vulns", [])
                for vuln in vulns:
                    findings.append(self._vuln_to_finding(dep, vuln))

        return findings

    @staticmethod
    def _vuln_to_finding(dep, vuln) -> Finding:
        """Transforme une entrée vuln OSV en Finding exploitable."""
        cve = next(
            (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
            vuln.get("id", ""),
        )
        severity = _severity_from_vuln(vuln)
        version_text = dep["version"] or dep["constraint"] or "?"
        summary = (vuln.get("summary") or vuln.get("details") or "").strip()
        if len(summary) > 240:
            summary = summary[:237] + "…"

        title = f"CVE : {dep['package']} {version_text}"
        if severity in ("critical", "high"):
            title = f"{title} ({cve})"

        return Finding(
            file=dep["manifest"], line=dep["line"],
            rule_id="dep-cve", category="dependencies",
            severity=severity, title=title,
            description=(
                f"{cve} — {summary}\n"
                f"Paquet : {dep['package']} {version_text} "
                f"(écosystème {dep['ecosystem']})."
            ),
            recommendation=(
                "Mettre à jour la dépendance vers une version corrigée. "
                "Consulter https://osv.dev/vulnerability/" + vuln.get("id", "")
            ),
            snippet=dep["constraint"], language=dep["ecosystem"],
            cve=cve, source="dependency_checker",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_requirements_like(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _normalize_version(raw: str):
    """Réduit une contrainte semver à une version exploitable (ou None)."""
    if not raw:
        return None
    v = raw.strip()
    if v in ("*", "latest", "next", "workspace:*", "file:*", ""):
        return None
    # ^1.2.3, ~1.2.3, >=1.2.3, >1.2, <=1.2, <1.2, !=1.2
    v = re.sub(r"^[\^~>=<\s]+", "", v)
    # version avec suffixe (x.y.z-beta) : on garde tel quel
    if not re.match(r"^v?\d+\.\d+(\.\d+)?", v):
        return None
    v = v.split(" ")[0].split(",")[0].strip()
    return v.lstrip("v") if v.startswith("v") else v


def _find_json_line(content: str, key: str) -> int:
    """Retrouve la ligne d'une clé dans un JSON (pour les rapports)."""
    m = re.search(rf'"{re.escape(key)}"\s*:', content)
    if not m:
        return 1
    return content.count("\n", 0, m.start()) + 1


def _severity_from_vuln(vuln: dict) -> str:
    """Déduit la sévérité d'une entrée OSV (GHSA ou score CVSS)."""
    # 1. Niveau fourni par la base (GHSA : database_specific.severity)
    db = vuln.get("database_specific") or {}
    level = str(db.get("severity", "")).upper()
    mapping = {
        "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
        "MEDIUM": "medium", "LOW": "low", "NONE": "low",
    }
    if level in mapping:
        return mapping[level]

    # 2. Score CVSS (vecteur de la forme CVSS:3.1/AV:…/A:H)
    for sev in vuln.get("severity") or []:
        vector = sev.get("score", "")
        if vector.startswith("CVSS:"):
            score = cvss_base_score(vector)
            if score is not None:
                return severity_from_cvss(score)

    # 3. Repli conservateur.
    return "high"


def severity_from_cvss(score: float) -> str:
    """Convertit un score CVSS (0-10) en niveau de sévérité."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def cvss_base_score(vector: str):
    """Calcule le score de base CVSS 3.x à partir d'un vecteur.

    Implémentation de la formule officielle FIRST (scope unchanged/changed).
    Renvoie None si le vecteur est illisible.
    """
    parts = {}
    for token in vector.split("/")[1:]:
        key, _, val = token.partition(":")
        parts[key] = val
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        scope_changed = parts.get("S", "U") == "C"
        pr_map = ({"N": 0.85, "L": 0.68, "H": 0.5}
                  if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27})
        pr = pr_map[parts["PR"]]
        c = {"H": 0.56, "L": 0.22, "N": 0}[parts["C"]]
        i = {"H": 0.56, "L": 0.22, "N": 0}[parts["I"]]
        a = {"H": 0.56, "L": 0.22, "N": 0}[parts["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        exploitability = 8.22 * av * ac * pr * ui
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            impact = 6.42 * iss
            base = min(impact + exploitability, 10.0)

        if impact <= 0:
            return 0.0
        # roundup à 1 décimale (arrondi supérieur)
        return math.ceil(base * 10) / 10
    except (KeyError, ValueError):
        return None

"""Exploration du système de fichiers et clonage de dépôts GitHub.

Ce module fournit :
  - `walk_files`   : parcours récursif des fichiers d'un projet,
                     avec filtrage des dossiers/fichiers ignorés et
                     détection de la langue par extension ;
  - `clone_repo`   : clonage d'un dépôt distant via `git clone`
                     (subprocess natif, sans GitPython) ;
  - `read_text_file`: lecture robuste d'un fichier texte (utf-8 puis
                     repli latin-1 pour éviter les erreurs d'encodage).
"""

import os
import shutil
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# Constantes de filtrage
# ---------------------------------------------------------------------------

# Dossiers toujours ignorés lors de l'exploration (dépendances, artefacts…).
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".idea",
    ".vscode", "dist", "build", ".next", ".nuxt", "vendor", ".gradle",
    ".mvn", "target", "coverage", "htmlcov", ".eggs", "site-packages",
    ".venv-win", ".terraform", ".cache",
}

# Extensions de fichiers binaires / artefacts à ignorer.
IGNORED_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".class", ".jar",
    ".o", ".a", ".obj", ".bin", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".mp3", ".mp4", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".sqlite", ".db", ".min.css",
    ".min.js", ".svg", ".map", ".lock", ".jks", ".keystore", ".p12", ".pfx",
}

# Association extension -> langage (utilisée par les analyseurs).
LANG_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".ps1": "powershell",
    ".pl": "perl",
    ".lua": "lua",
    ".r": "r",
    ".scala": "scala",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss",
    ".sql": "sql",
    ".xml": "xml",
    ".json": "json",
    ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml",
    ".ini": "ini", ".cfg": "ini",
    ".md": "markdown",
    ".txt": "text",
}

# Fichiers de configuration sensibles (mots de passe en clair possibles).
CONFIG_FILENAMES = {".env", ".env.local", ".env.production", ".env.development"}
CONFIG_EXTENSIONS = {".json", ".yml", ".yaml", ".ini", ".toml", ".cfg", ".xml"}

# Manifestes de dépendances reconnus par dependency_checker.
MANIFEST_FILENAMES = {
    "requirements.txt", "requirements-dev.txt", "dev-requirements.txt",
    "package.json", "composer.json", "Pipfile", "poetry.lock",
    "Gemfile", "Gemfile.lock", "go.mod", "Cargo.toml", "pom.xml",
}

# Fichiers de verrouillage générés AUTOMATIQUEMENT (npm/yarn/pnpm/bun…).
# Ils ne contiennent jamais de secret, mais des noms de paquets ou des
# hachages d'intégrité qui font naître des faux positifs (ex. le paquet
# « js-tokens » déclenche la règle « token »). On les ignore.
# NB : les fichiers d'extension `.lock` (Gemfile.lock, poetry.lock…) sont
# déjà exclus via IGNORED_EXTENSIONS.
LOCKFILE_NAMES = {
    "package-lock.json", "package-lock.yaml", "pnpm-lock.yaml",
    "yarn.lock", "bun.lock", "bun.lockb", "npm-shrinkwrap.json",
    "composer.lock", "Cargo.lock", "go.sum", "Pipfile.lock",
}

# Taille maximale d'un fichier analysé (au-delà, il est ignoré).
MAX_FILE_BYTES = 2_000_000


def is_requirements_file(name: str) -> bool:
    """True si `name` ressemble à un fichier requirements*.txt."""
    return name.startswith("requirements") and name.endswith(".txt")


# ---------------------------------------------------------------------------
# Modèle d'un fichier exploré
# ---------------------------------------------------------------------------

class SourceFile:
    """Un fichier rencontré lors de l'exploration du projet."""

    __slots__ = ("path", "relpath", "language", "kind")

    def __init__(self, path: str, relpath: str, language: str, kind: str):
        self.path = path          # chemin absolu sur disque
        self.relpath = relpath    # chemin relatif au projet (séparateurs '/')
        self.language = language  # langage détecté, "" si inconnu
        self.kind = kind          # "python" | "source" | "config" | "manifest"

    def __repr__(self):
        return f"<SourceFile {self.relpath} [{self.kind}]>"


# ---------------------------------------------------------------------------
# Exploration
# ---------------------------------------------------------------------------

def is_binary(chunk: bytes) -> bool:
    """Détecte un fichier binaire via la présence d'octets nuls."""
    return b"\x00" in chunk


def _classify(path: str, relpath: str) -> SourceFile:
    """Classifie un fichier : langage + type (source, config, manifest).

    Renvoie un SourceFile pour tout fichier digne d'intérêt.
    """
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]

    # Manifeste de dépendances
    if name in MANIFEST_FILENAMES or is_requirements_file(name):
        return SourceFile(path, relpath, "", "manifest")

    # Fichier de configuration sensible (.env, config.env, .env.local…)
    if name in CONFIG_FILENAMES or ext == ".env" or ext in CONFIG_EXTENSIONS:
        return SourceFile(path, relpath, LANG_BY_EXT.get(ext, ""), "config")

    # Fichier source (extensions connues)
    if ext in LANG_BY_EXT:
        lang = LANG_BY_EXT[ext]
        kind = "python" if lang == "python" else "source"
        return SourceFile(path, relpath, lang, kind)

    return None


def walk_files(root: str, verbose: bool = False) -> list:
    """Parcourt récursivement `root` et renvoie la liste des fichiers analysables."""
    root = os.path.abspath(root)
    files = []
    if verbose:
        print(f"[crawler] Exploration de {root}")

    for dirpath, dirnames, filenames in os.walk(root):
        # On filtre les dossiers en place pour que os.walk ne descende pas dedans.
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORED_DIRS and not d.startswith(".")
        ]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            name = fname.lower()
            ext = os.path.splitext(name)[1]

            # Fichiers de verrouillage générés automatiquement
            if name in LOCKFILE_NAMES:
                continue
            # Artefacts/binaires
            if ext in IGNORED_EXTENSIONS:
                continue
            # Fichiers trop volumineux (probablement générés/minifiés)
            try:
                if os.path.getsize(fpath) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue

            rel = os.path.relpath(fpath, root).replace("\\", "/")
            sf = _classify(fpath, rel)
            if sf is None:
                continue

            # Détection de binaire sur les premiers octets
            try:
                with open(fpath, "rb") as fh:
                    chunk = fh.read(1024)
            except OSError:
                continue
            if is_binary(chunk):
                continue

            files.append(sf)
            if verbose:
                print(f"  {rel} [{sf.kind}]")

    return files


# ---------------------------------------------------------------------------
# Clonage de dépôt
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str, dest: str = None, verbose: bool = False) -> str:
    """Clone un dépôt distant dans un dossier (temporaire par défaut).

    Utilise `git clone --depth 1` via subprocess (aucune dépendance).
    Renvoie le chemin du dossier cloné. Lève RuntimeError en cas d'échec.
    """
    if not dest:
        dest = tempfile.mkdtemp(prefix="codescan_")
    if verbose:
        print(f"[crawler] Clonage de {repo_url} …")
    try:
        cmd = ["git", "clone", "--depth", "1", "--quiet", repo_url, dest]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "").strip()
            raise RuntimeError(f"git clone a échoué : {msg}")
    except FileNotFoundError:
        raise RuntimeError(
            "git n'est pas installé ou introuvable dans le PATH."
        ) from None
    return dest


def cleanup_dir(path: str) -> None:
    """Supprime récursivement un dossier temporaire (ignore les erreurs)."""
    if path:
        shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Lecture
# ---------------------------------------------------------------------------

def read_text_file(path: str) -> str:
    """Lit un fichier texte en gérant l'encodage.

    Tente d'abord un décodage utf-8 strict, puis bascule en latin-1 si le
    fichier contient des octets non-utf8 (évite de planter l'analyse).
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except (UnicodeDecodeError, OSError):
        with open(path, "r", encoding="latin-1", errors="replace") as fh:
            return fh.read()

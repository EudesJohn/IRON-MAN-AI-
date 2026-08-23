"""Rapport d'audit **PDF**, 100 % bibliothèque standard (zlib).

IRON MAN AI produit « l'audit complet en PDF » sans aucune dépendance
externe ni rendu navigateur : on écrit un PDF minimaliste (compatible
lecteurs PDF) avec les polices standard Helvetica / Helvetica-Bold et des
flux de contenu compressés (FlateDecode). Le texte est paginé en A4 avec
en-tête, score, synthèse par sévérité, résultat par outil et détail des
relevés groupés par outil.

Utilisation :
    from kali.pdf import write_web_pdf
    write_web_pdf(findings, by_tool, target, meta, preflight, "audit.pdf", score)
"""

import zlib
from datetime import datetime

PAGE_W = 595.276   # A4 portrait (points)
PAGE_H = 841.89
MARGIN = 45
TOP = 58
BOTTOM = 42
CONTENT_W = PAGE_W - 2 * MARGIN

# Sévérités -> couleur RGB (0..1) pour le texte imprimé.
SEV_COLOR = {
    "critical": "0.86 0.15 0.15",
    "high": "0.92 0.35 0.06",
    "medium": "0.79 0.55 0.03",
    "low": "0.16 0.65 0.29",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
GRAY = "0.45 0.49 0.56"
INK = "0.09 0.1 0.13"          # texte courant (foncé, sur fond blanc)
BRAND = "0.72 0.13 0.11"       # rouge de marque pour le titre
RULE_COLOR = "0.8 0.82 0.86"

# Largeurs Helvetica (unités / 1000 em) — table ASCII standard.
_CHAR_W = {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667,
    "'": 191, "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333,
    ".": 278, "/": 278, "0": 556, "1": 556, "2": 556, "3": 556, "4": 556,
    "5": 556, "6": 556, "7": 556, "8": 556, "9": 556, ":": 278, ";": 278,
    "<": 584, "=": 584, ">": 584, "?": 556, "@": 1015,
    "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722,
    "O": 778, "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722,
    "V": 667, "W": 944, "X": 667, "Y": 667, "Z": 611,
    "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556, "`": 333,
    "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278, "g": 556,
    "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556,
    "o": 556, "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556,
    "v": 500, "w": 722, "x": 500, "y": 500, "z": 500,
    "{": 334, "|": 260, "}": 334, "~": 584,
}

# Unicode courant -> octet WinAnsi (police standard ; le reste hors latin-1
# devient « ? »).
_ANSI = {
    "‘": "",   # ' apostrophe guillemet gauche
    "’": "",   # '
    "“": "",   # "
    "”": "",   # "
    "•": "",   # •
    "–": "",   # –
    "—": "",   # —
    "…": "",   # …
}


def _win_ansi(text: str) -> str:
    """Ramène `text` à l'encodage WinAnsi des polices standard PDF."""
    out = []
    for ch in str(text):
        mapped = _ANSI.get(ch)
        if mapped is not None:
            out.append(mapped)
        elif ord(ch) < 256:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _esc_text(text: str) -> str:
    """Échappe une chaîne pour un littéral PDF (parenthèses, backslash)."""
    s = _win_ansi(text)
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _text_width(text: str, size: float) -> float:
    units = sum(_CHAR_W.get(ch, 556) for ch in text)
    return units * size / 1000.0


def _wrap(text: str, size: float, max_w: float) -> list:
    """Découpe `text` en lignes qui tiennent dans `max_w` (largeur points)."""
    words = str(text).split()
    if not words:
        return [""]
    lines = []
    cur = ""
    for w in words:
        trial = w if not cur else cur + " " + w
        if _text_width(trial, size) <= max_w or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


# --- Mise en page ------------------------------------------------------------

class _Doc:
    """Pagineur A4 : « y » = distance depuis le haut de la page, croissante
    vers le bas ; un saut de page est déclenché avant le bas de la page."""

    def __init__(self, title: str):
        self.title = title
        self.pages = [[]]   # page -> liste d'instructions
        self.y = TOP

    @property
    def page(self):
        return self.pages[-1]

    def new_page(self):
        self.pages.append([])
        self.y = TOP

    def ensure(self, height: float):
        if self.y + height > PAGE_H - BOTTOM:
            self.new_page()

    @staticmethod
    def line_height(size: float) -> float:
        return size * 1.35

    def text(self, text, size=9.5, font="r", color=INK, gap=2.0,
             indent=0.0):
        """Écrit un paragraphe en gérant le retour à la ligne."""
        max_w = CONTENT_W - indent
        lh = self.line_height(size)
        for ln in _wrap(text, size, max_w):
            self.ensure(lh + gap)
            self.page.append(("T", MARGIN + indent, self.y, size, font, ln,
                              color))
            self.y += lh
        self.y += gap

    def heading(self, text, size=12.0, gap=6.0, color=INK):
        lh = self.line_height(size)
        self.ensure(lh + gap + 2)
        self.page.append(("T", MARGIN, self.y, size, "b", text, color))
        self.y += lh + gap

    def rule(self, color=RULE_COLOR, gap=5.0, width=CONTENT_W):
        self.ensure(2.0 + gap)
        self.page.append(("R", MARGIN, self.y - 2.0, width, 0.9, color))
        self.y += 2.0 + gap

    def space(self, h=6.0):
        self.y += h

    def columns(self, row):
        """Une ligne « tableau » : liste de (x, text, size, font, color)."""
        lh = self.line_height(9.5)
        self.ensure(lh + 2.0)
        for x, text, size, font, color in row:
            self.page.append(("T", x, self.y, size, font, text, color))
        self.y += lh + 2.0


# --- Sérialisation PDF -------------------------------------------------------

def _serialize_page(ops: list) -> bytes:
    """Construit le flux de contenu (non compressé) d'une page.

    Les coordonnées sont données « du haut de la page » (top-down) ; les
    opérateurs PDF ont l'origine en bas à gauche : on convertit y -> PAGE_H-y.
    """
    buf = []
    for op in ops:
        if op[0] == "T":
            _, x, y, size, font, text, color = op
            fkey = "F2" if font == "b" else "F1"
            pdf_y = PAGE_H - y
            if color:
                buf.append(f"{color} rg ")
            buf.append(
                f"BT /{fkey} {size:.1f} Tf 1 0 0 1 {x:.1f} {pdf_y:.1f} Tm "
                f"({_esc_text(text)}) Tj ET\n")
        elif op[0] == "R":
            _, x, y, w, h, color = op
            pdf_y = PAGE_H - (y + h)
            buf.append(f"{color} rg {x:.1f} {pdf_y:.1f} {w:.1f} {h:.1f} re f\n")
    return "".join(buf).encode("latin-1", "replace")


def _build_pdf(ops_by_page: list) -> bytes:
    """Assemble les objets PDF (catalogue, pages, polices, flux) + xref."""
    streams = [_serialize_page(ops) for ops in ops_by_page]
    objs = []   # index 0 -> objet n°1

    def add(body: bytes) -> int:
        objs.append(body)
        return len(objs)

    # Objets fixes : catalogue, pages, puis polices standard.
    add(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1
    add(b"<< >>")                              # 2 (pages, rempli plus bas)
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>")      # 3 = F1
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
        b"/Encoding /WinAnsiEncoding >>")      # 4 = F2

    kids, contents = [], []
    for _ in streams:
        kids.append(add(b"<< >>"))    # objet page (placeholder)
        contents.append(add(b"<< >>"))  # objet flux (placeholder)

    # Flux de contenu compressés (FlateDecode).
    raw = [zlib.compress(s) for s in streams]

    objs[1] = (
        b"<< /Type /Pages /Kids ["
        + b" ".join(f"{k} 0 R".encode() for k in kids)
        + b"] /Count " + str(len(kids)).encode() + b" >>"
    )
    for i, stream in enumerate(raw):
        kid, cid = kids[i], contents[i]
        objs[kid - 1] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
            + f"{PAGE_W:.1f} {PAGE_H:.1f}".encode()
            + b"] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            b"/Contents " + str(cid).encode() + b" 0 R >>"
        )
        objs[cid - 1] = (
            b"<< /Length " + str(len(stream)).encode()
            + b" /Filter /FlateDecode >>\nstream\n" + stream
            + b"\nendstream"
        )

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode()
        out += body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(out)


# --- Contenu du rapport ------------------------------------------------------

def _by_severity(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _render(doc: _Doc, findings, by_tool, target_url, meta, preflight, score):
    """Remplit `doc` avec le contenu de l'audit complet."""
    tool_name = meta.get("tool", "IRON MAN AI")
    version = meta.get("version", "")
    now = meta.get("timestamp", datetime.now().isoformat(timespec="seconds"))
    total = len(findings)

    # --- En-tête -------------------------------------------------------------
    doc.heading("IRON MAN AI", size=20, gap=2, color=BRAND)
    doc.text("Audit de sécurité d'un site web — rapport complet (PDF)",
             size=11, gap=6)
    doc.text(f"Cible : {target_url}", size=10, gap=2)
    doc.text(f"Généré le {now} · {tool_name} v{version}", size=8, gap=4)
    doc.rule(gap=8)

    # --- Score ---------------------------------------------------------------
    if score:
        doc.heading("Score global", size=12, gap=4)
        sc = score.get("score", 0)
        grade = score.get("grade", "F")
        doc.text(f"Score web : {sc}/100  (niveau {grade}) — plus il est "
                 f"faible, mieux la cible est durcie.", size=10, gap=6)
        doc.space(2)

    # --- Synthèse par sévérité ----------------------------------------------
    doc.heading("Synthèse", size=12, gap=4)
    counts = _by_severity(findings)
    doc.text(f"Total de relevés : {total}", size=10, gap=3)
    for key, label in [
        ("critical", "Critique"), ("high", "Haute moyenne"),
        ("medium", "Moyenne"), ("low", "Basse"),
    ]:
        if counts[key]:
            doc.text(f"   {label} : {counts[key]}", size=9.5,
                     color=SEV_COLOR[key], gap=1.5)
    doc.rule(gap=6)

    # --- Résultat par outil --------------------------------------------------
    doc.heading("Résultats par outil", size=12, gap=4)
    if by_tool:
        doc.columns([
            (MARGIN, "Outil", 9.5, "b", GRAY),
            (MARGIN + 150, "Statut", 9.5, "b", GRAY),
            (MARGIN + 260, "Durée", 9.5, "b", GRAY),
            (MARGIN + 340, "Relevés", 9.5, "b", GRAY),
        ])
        for name, info in by_tool.items():
            status = info.get("status", "?")
            dur = info.get("duration_sec", 0)
            count = info.get("count", 0)
            ok = info.get("ok")
            color = ("0.16 0.65 0.29" if ok else
                     ("0.92 0.35 0.06" if status == "timeout"
                      else "0.86 0.15 0.15"))
            doc.columns([
                (MARGIN, name, 9.5, "r", INK),
                (MARGIN + 150, status, 9.5, "r", color),
                (MARGIN + 260, f"{dur:.0f}s", 9.5, "r", INK),
                (MARGIN + 340, str(count), 9.5, "r", INK),
            ])
    doc.rule(gap=6)

    # --- Préflight -----------------------------------------------------------
    doc.heading("Préflight (outils présents)", size=12, gap=4)
    if preflight:
        for name, info in preflight.items():
            present = info.get("present", False)
            mark = "présent" if present else "manquant"
            color = "0.16 0.65 0.29" if present else "0.86 0.15 0.15"
            doc.text(f"  {name:<12} {mark}", size=9.5, color=color, gap=1.5)
    doc.rule(gap=6)

    # --- Détail des relevés --------------------------------------------------
    doc.heading(f"Détail des relevés ({total})", size=12, gap=4)
    if not findings:
        doc.text("Aucun relevé de sécurité détecté par les outils lancés.",
                 size=10, gap=2)
        return

    by_source = {}
    for f in findings:
        by_source.setdefault(f.source, []).append(f)

    for source in by_tool or by_source:
        items = sorted(by_source.get(source, []),
                       key=lambda f: (SEV_ORDER.get(f.severity, 4), f.rule_id))
        if not items:
            continue
        doc.rule(color=RULE_COLOR, gap=3)
        doc.text(f"Outil : {source}  ({len(items)} relevé(s))", size=11,
                 font="b", gap=5)
        for f in items:
            color = SEV_COLOR.get(f.severity, INK)
            header = f"[{f.severity.upper()}] {f.rule_id}  {f.title}"
            lh = doc.line_height(9.5)
            for ln in _wrap(header, 9.5, CONTENT_W):
                doc.ensure(lh + 1.0)
                doc.page.append(("T", MARGIN, doc.y, 9.5, "b", ln, color))
                doc.y += lh
            doc.y += 1.0
            if f.description:
                doc.text(f"   {f.description}", size=8.8, gap=1.5)
            if f.recommendation:
                doc.text(f"   Correction : {f.recommendation}", size=8.8,
                         color="0.16 0.65 0.29", gap=1.5)
            if f.snippet:
                for ln in _wrap(f.snippet, 7.5, CONTENT_W - 16):
                    doc.ensure(doc.line_height(7.5) + 1.5)
                    doc.page.append(
                        ("T", MARGIN + 8, doc.y, 7.5, "r", ln, INK))
                    doc.y += doc.line_height(7.5)
                doc.y += 2.0
            doc.space(3)


def build_pdf_bytes(findings, by_tool, target_url, meta, preflight,
                    score=None) -> bytes:
    """Construit les octets du rapport PDF complet."""
    doc = _Doc("IRON MAN AI")
    _render(doc, findings, by_tool, target_url, meta, preflight, score)
    return _build_pdf(doc.pages)


def write_web_pdf(findings, by_tool, target_url, meta, preflight,
                  output_path: str, score=None) -> None:
    """Écrit le rapport d'audit au format PDF sur `output_path`."""
    data = build_pdf_bytes(findings, by_tool, target_url, meta, preflight,
                           score)
    with open(output_path, "wb") as fh:
        fh.write(data)
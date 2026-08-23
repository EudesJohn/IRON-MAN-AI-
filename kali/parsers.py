"""Parseurs de sorties d'outils du mode WebScan Kali.

Chaque parseur convertit la sortie brute d'un outil (stdout) en une liste
de `scanner.models.Finding`, avec des IDs de règle anglais kebab-case
(`web-*`), des descriptions en français et des catégories compatibles avec
le scorer (`injection`, `xss`, `security_misc`).

Les parseurs sont volontairement robustes : ils lisent ligne par ligne,
ignorent les lignes vides et ne tombent jamais en erreur sur une sortie
inattendue (ils renvoient alors une liste vide).
"""

import json
import re

from scanner.models import Finding
from kali.exploits import get_simple_explanation, resolve_simple_explanation, DEFAULT_CREDENTIALS, ADMIN_PATHS

# Sanitize un identifiant de template nuclei en kebab-case sûr.
_SAFE_ID = re.compile(r"[^a-z0-9]+")


def _finding(tool: str, rule_id: str, severity: str, title: str,
             description: str = "", recommendation: str = "",
             snippet: str = "", category: str = "security_misc",
             target: dict = None,
             exploitation: str = "", attack_vector: str = "",
             impact: str = "", admin_panel: str = "") -> Finding:
    """Fabrique un Finding du mode web (file = URL de la cible).

    Ajoute automatiquement l'explication simple si la catégorie est connue.
    """
    # Enrichir avec l'explication simple si disponible
    simple = resolve_simple_explanation(rule_id, category, severity)
    if simple and not exploitation:
        exploitation = simple.get("explanation", "")
    if simple and not impact:
        impact = simple.get("danger", "")
    if simple and not title:
        title = simple.get("title", title)

    return Finding(
        file=target["url"] if target else "web",
        line=0,
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        snippet=snippet[:400],
        language="web",
        source=tool,
        exploitation=exploitation,
        attack_vector=attack_vector,
        impact=impact,
        admin_panel=admin_panel,
    )


# ---------------------------------------------------------------------------
# Parseurs individuels (un par outil)
# ---------------------------------------------------------------------------

def parse_nmap(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)/tcp\s+(open|filtered)\s+(\S+)\s*(.*)$", line)
        if m:
            port, state, service, ver = m.group(1), m.group(2), m.group(3), m.group(4)
            v = ver.strip()
            # --- Exploitation détaillée par service ---
            svc_lower = service.lower()
            if svc_lower == "http" or svc_lower == "https":
                expl = (
                    f"Un attaquant peut interroger le serveur HTTP sur le port {port}. "
                    f"Vecteurs : fuzzing des URL, injection de headers, "
                    f"exploitation de vulnérabilités du serveur web ({v}), "
                    f"scan des répertoires cachés (gobuster/dirsearch), "
                    f"injection SQL/XSS via les formulaires.")
                impact = "Reconnaissance avancée, vol de données, exécution de code à distance"
            elif svc_lower in ("ssh", "telnet"):
                expl = (
                    f"Le service {service} ({v}) est exposé. "
                    f"Vecteurs : brute-force (hydra/medusa), exploitation de CVE connues, "
                    f" credentials par défaut, clefs SSH faibles. "
                    f"Un accès SSH donne un shell complet sur le serveur.")
                impact = "Accès complet au serveur (shell), pivot vers l'interne"
            elif svc_lower == "ftp":
                expl = (
                    f"FTP ouvert ({v}). Vecteurs : authentification anonyme, "
                    f"brute-force des identifiants, FTP non chiffré (données en clair), "
                    f"déversement de fichiers sensibles.")
                impact = "Vol de fichiers, upload de malware, pivot"
            elif svc_lower in ("mysql", "postgresql", "mssql", "oracle"):
                expl = (
                    f"Base de données {service} ({v}) exposée sur le réseau. "
                    f"Vecteurs : brute-force, injection SQL directe, "
                    f"exécution de commandes côté serveur (xp_cmdshell, COPY TO).")
                impact = "Vol/extraction complète de la base de données, RCE"
            elif svc_lower == "smtp":
                expl = (
                    f"SMTP ({v}) exposé. Vecteurs : enumération d'utilisateurs (VRFY/EXPN), "
                    f"open relay pour phishing, brute-force des identifiants mail.")
                impact = "Phishing, spam, vol d'identifiants"
            elif svc_lower in ("dns", "domain"):
                expl = (
                    f"DNS ({v}) exposé. Vecteurs : zone transfer (AXFR), "
                    f"DNS cache poisoning, énumération de sous-domaines.")
                impact = "Reconnaissance, redirection de trafic"
            else:
                expl = (
                    f"Le service {service} ({v}) est exposé sur le port {port}. "
                    f"Un attaquant peut scanner ce service pour trouver des CVE, "
                    f"brute-force les identifiants, ou exploiter des failles connues.")
                impact = "Reconnaissance, potentiel accès non autorisé"
            out.append(_finding(
                "nmap", "web-nmap-open-port", "low",
                f"Port {port}/tcp ouvert ({service})",
                f"Le port {port}/tcp est {state} avec le service {service} ({v}).",
                "Fermer les ports inutiles et s'assurer que le service est à jour.",
                snippet=line, target=target,
                exploitation=expl, attack_vector="network",
                impact=impact))
    return out


def parse_nikto(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        if line.lstrip().startswith("+"):
            severity = "high" if re.search(r"\b(critical|high)\b", line, re.I) else "medium"
            detail = line.strip("+ ").strip()
            detail_lower = detail.lower()
            # Exploitation détaillée selon le type de finding nikto
            if "directory indexing" in detail_lower or "listing" in detail_lower:
                expl = (
                    "L'indexation de répertoire expose la liste complète des fichiers. "
                    "Un attaquant peut naviguer dans l'arborescence, télécharger des "
                    "fichiers de configuration, des backups, des sources, ou trouver "
                    "des fichiers contenant des mots de passe ou des clés API.")
                impact = "Vol de données, fuite de configuration, énumération"
            elif "header" in detail_lower and ("missing" in detail_lower or "x-frame" in detail_lower or "content-security" in detail_lower):
                expl = (
                    "Un en-tête de sécurité manquant (X-Frame-Options, CSP, HSTS…) "
                    "permet : clickjacking (clics piégés via iframes), "
                    "exfiltration de données via XSS, downgrade HTTP→HTTPS.")
                impact = "Clickjacking, XSS stocké, interception de données"
            elif "cookie" in detail_lower and ("missing" in detail_lower or "httponly" in detail_lower or "secure" in detail_lower):
                expl = (
                    "Un cookie sans flags HttpOnly/Secure peut être volé par JavaScript "
                    "(via XSS) ou intercepté en clair (HTTP). L'attaquant dérobe le "
                    "session ID et prend le contrôle du compte utilisateur.")
                impact = "Vol de session, prise de contrôle de compte"
            elif "backup" in detail_lower or "old backup" in detail_lower:
                expl = (
                    "Un fichier backup exposé contient potentiellement le code source, "
                    "des identifiants de base de données, ou des configurations. "
                    "L'attaquant le télécharge et extrait les secrets.")
                impact = "Vol de code source, fuite de credentials, RCE"
            elif "admin" in detail_lower or "login" in detail_lower:
                expl = (
                    "La page d'administration ou de connexion est accessible. "
                    "L'attaquant peut tenter un brute-force (hydra/medusa), "
                    "injection SQL dans le formulaire, ou exploiter des failles d'auth.")
                impact = "Accès administrateur, contrôle total de l'application"
            else:
                expl = (
                    f"Nikto a détecté une anomalie de configuration : {detail}. "
                    f"Un attaquant peut exploiter cette faiblesse pour accéder "
                    f"à des ressources protégées ou obtenir des informations sur le serveur.")
                impact = "Reconnaissance, énumération, potentiel accès"
            out.append(_finding(
                "nikto", "web-nikto-finding", severity,
                "Nikto a détecté un problème",
                detail,
                "Vérifier la configuration du serveur et corriger le point relevé.",
                snippet=line.strip(), target=target,
                exploitation=expl, attack_vector="network",
                impact=impact))
    return out


def parse_whatweb(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        if "[" in line and ("OK" in line or "http" in line):
            m = re.search(r"\[(\d{3})\s+\S+\].*", line)
            techs = line.split("]")[-1].strip() if "]" in line else ""
            if techs and not techs.startswith("http"):
                out.append(_finding(
                    "whatweb", "web-whatweb-tech", "low",
                    "Technologies web détectées",
                    f"Technologies identifiées : {techs}.",
                    "Inventorier les technologies pour connaître la surface d'attaque.",
                    snippet=techs[:200], target=target))
    return out


def parse_gobuster(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        m = re.search(r"^(/[\w\-./]*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            path = m.group(1)
            code = m.group(2)
            sev = "low"
            is_admin = False
            # Détection des chemins admin critiques
            admin_keywords = ("admin", "wp-admin", "cpanel", "phpmyadmin",
                             "dashboard", "manage", "backend", "console",
                             "manager", "webadmin", "server-status",
                             "server-info", ".env", "config", "backup",
                             ".git", ".svn", "debug", "test", "staging")
            if any(kw in path.lower() for kw in admin_keywords):
                is_admin = True
                sev = "high"
            elif code == "200":
                sev = "medium"
            expl = (
                f"Le chemin {path} répond HTTP {code}. "
                + (f"C'est potentiellement un panneau d'administration accessible. "
                   f"Un attaquant peut tenter un brute-force sur le formulaire "
                   f"de connexion, injecter du SQL, ou exploiter des failles d'auth." if is_admin
                   else f"Un attaquant peut inspecter le contenu, chercher des fichiers "
                   f"sensibles (config, backup, .env, .git), ou utiliser cette URL "
                   f"comme point d'entrée pour des attaques ciblées."))
            impact = (
                "Accès administrateur, contrôle total" if is_admin
                else "Énumération, découverte de surface d'attaque")
            out.append(_finding(
                "gobuster", "web-gobuster-dir", sev,
                f"{'Panneau admin' if is_admin else 'Chemin'} découvert (HTTP {code})",
                f"Le chemin {path} répond avec le code {code}.",
                ("Sécuriser l'accès admin (auth forte, IP restreinte, 2FA)" if is_admin
                 else "S'assurer que les répertoires découverts ne révèlent pas de données sensibles."),
                snippet=line.strip(), target=target,
                exploitation=expl, attack_vector="network",
                impact=impact,
                admin_panel=(target["url"].rstrip("/") + path if is_admin else "")))
    return out


def parse_dirsearch(stdout: str, target: dict) -> list:
    out = []
    # Format réel : « [14:00:01] 200 -   3KB - /admin/ » (code, taille, chemin).
    for line in stdout.splitlines():
        m = re.search(r"\b(\d{3})\s+-\s+\S+\s+-\s+(\S+)", line)
        if m:
            code, path = m.group(1), m.group(2)
            is_admin = False
            admin_keywords = ("admin", "wp-admin", "cpanel", "phpmyadmin",
                             "dashboard", "manage", "backend", "console",
                             "manager", "webadmin", ".env", "config",
                             "backup", ".git", "debug", "login", "wp-login")
            if any(kw in path.lower() for kw in admin_keywords):
                is_admin = True
            sev = "high" if is_admin else ("medium" if code == "200" else "low")
            expl = (
                f"dirsearch a trouvé le chemin {path} (HTTP {code}). "
                + (f"C'est un point d'entrée potentiel pour l'attaquant : "
                   f"brute-force du formulaire, injection SQL/XSS, "
                   f"fichiers de configuration exposés." if is_admin
                   else f"Le contenu peut révéler des informations sur "
                   f"l'architecture de l'application."))
            impact = (
                "Accès administrateur" if is_admin
                else "Énumération, découverte de surface d'attaque")
            out.append(_finding(
                "dirsearch", "web-dirsearch-dir", sev,
                f"{'Panneau admin' if is_admin else 'Chemin'} découvert (HTTP {code})",
                f"dirsearch a trouvé le chemin {path} (code {code}).",
                "Vérifier le contenu des chemins découverts.",
                snippet=line.strip(), target=target,
                exploitation=expl, attack_vector="network",
                impact=impact,
                admin_panel=(target["url"].rstrip("/") + path if is_admin else "")))
    return out


def parse_sslscan(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        low = "SSLv3" in line or "SSLv2" in line or "TLSv1.0" in line
        weak_cipher = "RC4" in line or "3DES" in line
        if low or weak_cipher:
            sev = "high" if low else "medium"
            proto = "SSLv2" if "SSLv2" in line else "SSLv3" if "SSLv3" in line else "TLSv1.0" if "TLSv1.0" in line else "RC4/3DES"
            expl = (
                f"Le protocole {proto} est vulnérable. "
                + (f"SSLv2 est cassable en quelques minutes (DROWN attack). "
                   f"SSLv3 est vulnérable au padding oracle (POODLE). " if low
                   else f"{proto} est faible et peut être déchiffré par force brute. ")
                + f"Un attaquant sur le réseau (MITM) peut intercepter et déchiffrer "
                f"le trafic (cookies, tokens, identifiants) en exploitant cette faiblesse.")
            impact = "Interception de données, vol de credentials, sniffing"
            out.append(_finding(
                "sslscan", "web-ssl-weak", sev,
                "Protocole TLS/SSL faible détecté",
                line.strip(),
                "Désactiver les protocoles obsolètes et les suites de chiffrement faibles.",
                snippet=line.strip(), target=target,
                exploitation=expl, attack_vector="network",
                impact=impact))
        elif re.search(r"(self.signed|expired|not trusted)", line, re.I):
            expl = (
                "Le certificat TLS n'est pas vérifié par un CA reconnu. "
                "Un attaquant peut générer un certificat frauduleux et "
                "intercepter le trafic (attaque MITM complète). "
                "Les utilisateurs verront un avertissement mais beaucoup le contournent.")
            impact = "Interception totale du trafic (MITM), vol de données"
            out.append(_finding(
                "sslscan", "web-tls-cert", "medium",
                "Certificat TLS non fiable",
                line.strip(),
                "Renouveler et configurer un certificat valide.",
                snippet=line.strip(), target=target,
                exploitation=expl, attack_vector="network",
                impact=impact))
    return out


def parse_nuclei(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        info = data.get("info", {}) or {}
        sev = str(info.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        if sev == "info":
            sev = "low"
        tid = str(info.get("name") or data.get("template-id") or "nuclei")
        rid = "web-nuclei-" + _SAFE_ID.sub("-", tid.lower()).strip("-")
        out.append(_finding(
            "nuclei", rid, sev,
            f"Templat nuclei : {tid}",
            str(info.get("description") or data.get("matched-at") or ""),
            "Corriger selon les recommandations du template nuclei.",
            snippet=line[:300], target=target))
    return out


def parse_wafw00f(stdout: str, target: dict) -> list:
    out = []
    for line in stdout.splitlines():
        if "is behind" in line.lower() or "waf" in line.lower():
            out.append(_finding(
                "wafw00f", "web-waf-detected", "low",
                "Pare-feu applicatif détecté",
                line.strip(),
                "Information : la cible est protégée par un WAF (à noter pour l'interprétation).",
                snippet=line.strip(), target=target))
    return out


def parse_dnsrecon(stdout: str, target: dict) -> list:
    out = []
    # dnsrecon indente ses enregistrements («    A  example.com.  IN A ... »).
    for line in stdout.splitlines():
        line = line.strip()
        m = re.search(r"^([A-Z]+\s+[\w.\-]+)\s+(IN\s+)?([\w.\-]+.*)$", line)
        if m and m.group(1).split()[0] in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            out.append(_finding(
                "dnsrecon", "web-dns-record", "low",
                f"Enregistrement DNS {m.group(1).split()[0]}",
                line.strip(),
                "Information DNS — vérifier que les enregistrements sont légitimes.",
                snippet=line.strip(), target=target))
    return out


# --- Palier attack ----------------------------------------------------------

def parse_sqlmap(stdout: str, target: dict) -> list:
    out = []
    text = stdout.lower()
    if "is not injectable" in text or "might not be injectable" in text:
        return out
    sqlmap_expl = (
        "L'injection SQL permet à un attaquant d'envoyer du SQL malveillant "
        "via les paramètres URL/formulaire. Conséquences possibles : "
        "1) Lecture de toutes les données (users, passwords, cards) "
        "via UNION SELECT. "
        "2) Écriture/déstruction de données (DROP TABLE, INSERT). "
        "3) Exécution de commandes OS si le serveur le permet (xp_cmdshell, INTO OUTFILE). "
        "4) Bypass d'authentification (' OR 1=1 --). "
        "5) Lecture de fichiers (/etc/passwd via LOAD_FILE).")
    sqlmap_impact = "Vol complet de la base de données, bypass d'auth, RCE"
    for line in stdout.splitlines():
        if re.search(r"\b(vulnerable|injectable)\b", line, re.I) or \
           (re.search(r"^payload:", line, re.I)):
            out.append(_finding(
                "sqlmap", "web-sqlmap-injectable", "critical",
                "Injection SQL détectée (sqlmap)",
                line.strip(),
                "Corriger en utilisant des requêtes paramétrées / ORM.",
                snippet=line.strip(), target=target, category="injection",
                exploitation=sqlmap_expl, attack_vector="network",
                impact=sqlmap_impact))
    if "parameter" in text and "is vulnerable" in text:
        for line in stdout.splitlines():
            m = re.search(r"parameter:\s*([\w]+).*", line, re.I)
            if m:
                out.append(_finding(
                    "sqlmap", "web-sqlmap-injectable", "critical",
                    f"Injection SQL détectée (paramètre {m.group(1)})",
                    line.strip(),
                    "Corriger en utilisant des requêtes paramétrées / ORM.",
                    snippet=line.strip(), target=target, category="injection",
                    exploitation=sqlmap_expl, attack_vector="network",
                    impact=sqlmap_impact))
                break
    return out


def parse_xsstrike(stdout: str, target: dict) -> list:
    out = []
    xss_expl = (
        "Le XSS (Cross-Site Scripting) permet d'injecter du JavaScript dans les pages "
        "vues par d'autres utilisateurs. Conséquences : "
        "1) Vol de cookies/session (document.cookie → exfiltration). "
        "2) Keylogging (enregistrer les frappes clavier). "
        "3) Pharming (rediriger vers un site malveillant). "
        "4) Défacement du site (innerHTML = '). "
        "5) Capture de formulaires (vol de mots de passe). "
        "6) Pivot vers l'interne si l'admin est affecté (XSS→RCE via CSRF).")
    xss_impact = "Vol de session, keylogging, phishing, defacement"
    for line in stdout.splitlines():
        if re.search(r"\b(xss|reflection)\b", line, re.I) and \
           ("found" in line.lower() or "reflections" in line.lower() or "payload" in line.lower()):
            out.append(_finding(
                "xsstrike", "web-xss-strike", "high",
                "XSS probable détecté (XSS Strike)",
                line.strip(),
                "Échapper les entrées et valider les sorties (Content-Security-Policy).",
                snippet=line.strip(), target=target, category="xss",
                exploitation=xss_expl, attack_vector="network",
                impact=xss_impact))
    return out


def parse_commix(stdout: str, target: dict) -> list:
    out = []
    rce_expl = (
        "L'injection de commandes OS (Command Injection) permet d'exécuter "
        "n'importe quelle commande système depuis le serveur. Conséquences : "
        "1) Reverse shell (attaquant obtient un accès interactif). "
        "2) Lecture de fichiers (/etc/passwd, /etc/shadow, config). "
        "3) Écriture de malware (wget + chmod + exec). "
        "4) Pivot vers d'autres machines du réseau interne. "
        "5) Chiffrement des données (ransomware). "
        "6) Minage de cryptomonnaie. "
        "7) Exfiltration de données vers un serveur externe.")
    rce_impact = "Exécution de code à distance (RCE), contrôle total du serveur"
    for line in stdout.splitlines():
        if re.search(r"\b(injectable|vulnerable)\b", line, re.I):
            out.append(_finding(
                "commix", "web-commix-injectable", "high",
                "Injection de commandes OS détectée (commix)",
                line.strip(),
                "Ne pas exécuter d'entrées utilisateur dans des commandes système.",
                snippet=line.strip(), target=target, category="injection",
                exploitation=rce_expl, attack_vector="network",
                impact=rce_impact))
    return out


def parse_hydra(stdout: str, target: dict) -> list:
    out = []
    brute_expl = (
        "Hydra a trouvé des identifiants valides par brute-force. "
        "Conséquences immédiates : "
        "1) Accès au panneau d'administration (contrôle total). "
        "2) Extraction de données sensibles (users, DB, config). "
        "3) Modification de contenu (defacement). "
        "4) Upload de webshell pour maintien d'accès. "
        "5) Pivot vers d'autres systèmes (si mêmes credentials). "
        "6) Exfiltration de données vers un serveur externe.")
    brute_impact = "Accès complet au système, vol de données, defacement"
    for line in stdout.splitlines():
        if re.search(r"\blogin:\s*\S+\s+password:\s*\S+", line, re.I) or \
           re.search(r"\[(\d+)\].*\bsuccess\b", line, re.I):
            out.append(_finding(
                "hydra", "web-hydra-credential", "critical",
                "Identifiants valides trouvés (hydra)",
                line.strip(),
                "Changer immédiatement les identifiants concernés.",
                snippet=line.strip(), target=target,
                exploitation=brute_expl, attack_vector="network",
                impact=brute_impact))
    return out


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

PARSERS = {
    "nmap": parse_nmap,
    "nikto": parse_nikto,
    "whatweb": parse_whatweb,
    "gobuster": parse_gobuster,
    "dirsearch": parse_dirsearch,
    "sslscan": parse_sslscan,
    "nuclei": parse_nuclei,
    "wafw00f": parse_wafw00f,
    "dnsrecon": parse_dnsrecon,
    "sqlmap": parse_sqlmap,
    "xsstrike": parse_xsstrike,
    "commix": parse_commix,
    "hydra": parse_hydra,
}


def parse_output(tool_name: str, stdout: str, target: dict) -> list:
    """Parse la sortie brute d'un outil en findings (liste vide si inconnu)."""
    parser = PARSERS.get(tool_name)
    if parser is None:
        return []
    return parser(stdout, target) or []
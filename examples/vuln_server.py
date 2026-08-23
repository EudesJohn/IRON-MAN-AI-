"""Serveur HTTP vulnérable de démonstration (mode WebScan Kali).

Petit serveur stdlib (`http.server`) agressivement peu sécurisé, destiné
uniquement à tester CodeScan WebScan Kali **en localhost** (cible que l'on
possède donc : parfaitement autorisée). Il expose volontairement :

  - une page d'accueil sans en-têtes de sécurité (X-Frame-Options, CSP…) ;
  - `/search?q=...` qui reflète l'entrée sans échappement (XSS réfléchi) ;
  - `/echo?id=...` qui concatène le paramètre dans une « requête » simulée
    (injection SQL d'exemple) ;
  - `/admin/*` un panneau fictif (faiblesses basiques) ;
  - d'autres chemins connus (robots.txt, login, api, debug…) pour que
    gobuster / dirsearch aient des cibles à trouver.

Usage :
    python examples/vuln_server.py [--port 8000]
    # puis, sur la même machine :
    python kali_scan.py --url http://127.0.0.1:8000 --authorized
"""

import argparse
import html as html_mod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>VulnShop — démo CodeScan WebScan</title></head>
<body>
<h1>Bienvenue sur VulnShop</h1>
<p>Site Web volontairement vulnérable (démo locale autorisée).</p>
<ul>
  <li><a href="/?q=salut">Recherche (XSS réfléchi)</a></li>
  <li><a href="/echo?id=42">Produit 42 (injection SQL d'exemple)</a></li>
  <li><a href="/admin/debug">Panneau interne (fictif)</a></li>
</ul>
<form method="get" action="/">
  <input name="q" placeholder="votre recherche">
  <button>Rechercher</button>
</form>
<hr>{result}</body>
</html>
"""


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silencieux (log API propre)
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        # Absence volontaire de "X-Frame-Options", "Content-Security-Policy",
        # "Strict-Transport-Security", etc. (faiblesse d'en-têtes).
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            q = (qs.get("q") or [""])[0]
            # XSS réfléchi : l'entrée est insérée brute dans la page
            # (sans échappement HTML) — équivalent d'un reflet d'erreur.
            reflected = f"<pre>Vous avez cherche : <b>{q}</b></pre>"
            body = PAGE.replace("{result}", reflected)
            self._send(body)

        elif path == "/echo":
            identifiant = (qs.get("id") or [""])[0]
            # Injection SQL d'exemple : concaténation non paramétrée.
            query = "SELECT * FROM produits WHERE id = '" + identifiant + "'"
            self._send(f"<pre>{query}\n-> '1' = '1' → TOUTE LA TABLE</pre>")

        elif path.startswith("/admin"):
            self._send("<h1>Panneau interne</h1><p>Réservé à l'équipe. "
                       "Aucune authentification réelle.</p><pre>user=admin "
                       "pass=admin123</pre>", code=403)

        elif path == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin/\nDisallow: /debug/\n",
                       ctype="text/plain")

        elif path in ("/api", "/health", "/status", "/login", "/debug", "/config"):
            self._send(f"<pre>endpoint {path} : {qs}</pre>")

        else:
            self._send("<h1>404</h1><a href='/'>retour</a>", code=404)

    do_POST = do_GET


def main():
    ap = argparse.ArgumentParser(description="Serveur vulnérable de démo.")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), VulnHandler)
    print(f"[vuln-server] http://127.0.0.1:{args.port}  (Ctrl+C pour arrêter)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[vuln-server] arrêt.")


if __name__ == "__main__":
    main()
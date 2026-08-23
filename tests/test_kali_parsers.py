"""Tests des parseurs du mode WebScan Kali (sorties réalises -> findings).

Les fixtures sont des extraits de sorties *réelles* d'outils (nmap, nikto,
nuclei, sqlmap…) encodées en UTF-8. Aucun outil externe n'est exécuté.
"""

import re
import unittest

from kali.parsers import parse_output, PARSERS
from scanner.models import severity_ge

TARGET = {"url": "http://example.com/", "host": "example.com",
          "scheme": "http", "port": 80, "path": "/", "domain": "example.com"}

NMAP_SAMPLE = """Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-08
Nmap scan report for example.com
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http          Apache httpd 2.4.41
443/tcp  open  ssl/http      nginx 1.18.0
"""

NIKTO_SAMPLE = """\
- Nikto v2.1.5
+ OSVDB-3092: /admin/: Admin page
+ OSVDB-3268: /config/: Directory listing found
+ Server: nginx/1.18.0
+ High: Some high level finding here
"""

GOBUSTER_SAMPLE = """\
/admin               (Status: 200) [Size: 3456]
/backup              (Status: 301) [Size: 0] --> /backup/
/config/.env         (Status: 401) [Size: 12]
"""

DIRSEARCH_SAMPLE = """\
[14:00:01] 200 -   3KB - /admin/
[14:00:02] 301 -    0B - /api   ->  /api/
[14:00:03] 200 -    2KB - /login
"""

SSLSCAN_SAMPLE = """\
Version: 2.0.4
  Hello_Extension_Type: EC point formats (3)
  OpenSSL: OpenSSL 3.0.5
  Accepted  SSLv3    256 bits  AES256-SHA
  Accepted  TLSv1.0  256 bits  AES256-SHA
  Attempting to connect to example.com:443
  Negotiated protocol: TLSv1.2 - Cipher: ECDHE-RSA-AES256-GCM-SHA384
"""

_VALID_NUCLEI = (
    '{"template-id":"cves/2024/CVE-2024-1234","info":{"name":"CVE-2024-1234",'
    '"severity":"critical","description":"RCE"},"matched-at":"http://example.com/"}\n'
    '{"template-id":"tech-detect","info":{"name":"tech detect","severity":"info",'
    '"description":"tech"},"matched-at":"http://example.com/"}\n'
)

WAFW00F_SAMPLE = """\
* WAFW00F - Web Application Firewall Detection Tool

Checking http://example.com
The site http://example.com is behind Cloudflare WAF.
"""

DNSRECON_SAMPLE = """\
[*] Performing Standard Enumeration
   A  example.com.  IN A  192.0.2.1
   A  www.example.com.  IN A  192.0.2.2
   MX  example.com.  IN MX  10 mail.example.com
   TXT  example.com.  "v=spf1 -all"
"""

SQLMAP_SAMPLE = """\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] heuristic (basic) test shows that GET parameter 'id' appears to be dynamic
[INFO] GET parameter 'id' is injectable
[PW] GET parameter 'id' is vulnerable. Do you want to keep testing the others?
[INFO] URI: http://example.com/echo?id=1
you provided the value 1
"""

XSSSTRIKE_SAMPLE = """\
[!] YOU CAN NOT BREAK OUT OF THE GODS, RUN! THE END IS NEAR!
[+] Reflections found: /echo?id=1
[+] XSS found!! payload: <script>alert(1)</script>
[+] XSS Strike steps:
"""

COMMIX_SAMPLE = """\
[+] URL: http://example.com/echo?id=1
[!] The following parameters are injectable:
[+] Injection point found (1/1)
[+] Parameter 'id' is injectable
"""

HYDRA_SAMPLE = """\
Hydra v8.6
[DATA] attacking http-get-form /login
[80][HTTP] host: example.com   login: admin   password: admin123
[STATUS] attack finished
"""


class TestNmapParser(unittest.TestCase):
    def test_parses_open_ports(self):
        fs = PARSERS["nmap"](NMAP_SAMPLE, TARGET)
        self.assertGreaterEqual(len(fs), 2)
        ports = set()
        for f in fs:
            self.assertEqual(f.rule_id, "web-nmap-open-port")
            m = re.match(r"(\d+)/tcp", f.snippet or "")
            if m:
                ports.add(m.group(1))
        self.assertIn("80", ports)
        self.assertIn("443", ports)

    def test_no_false_positives_on_clean_output(self):
        self.assertEqual(PARSERS["nmap"]("PORT STATE SERVICE", TARGET), [])


class TestNiktoParser(unittest.TestCase):
    def test_findings_severity(self):
        fs = PARSERS["nikto"](NIKTO_SAMPLE, TARGET)
        self.assertTrue(fs)
        severities = [f.severity for f in fs]
        self.assertIn("high", severities)  # ligne « High: ... »
        for f in fs:
            self.assertEqual(f.rule_id, "web-nikto-finding")
            self.assertEqual(f.category, "security_misc")


class TestGobusterAndDirsearch(unittest.TestCase):
    def test_gobuster(self):
        fs = PARSERS["gobuster"](GOBUSTER_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].rule_id, "web-gobuster-dir")
        self.assertIn("admin", fs[0].snippet)

    def test_dirsearch(self):
        fs = PARSERS["dirsearch"](DIRSEARCH_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].rule_id, "web-dirsearch-dir")


class TestSslscanParser(unittest.TestCase):
    def test_weak_protocol_detected(self):
        fs = PARSERS["sslscan"](SSLSCAN_SAMPLE, TARGET)
        self.assertTrue(fs)
        ids = {f.rule_id for f in fs}
        self.assertIn("web-ssl-weak", ids)


class TestNucleiParser(unittest.TestCase):
    def test_jsonl(self):
        fs = PARSERS["nuclei"](_VALID_NUCLEI, TARGET)
        self.assertTrue(fs)
        severe = [f for f in fs if f.severity == "critical"]
        self.assertEqual(len(severe), 1)
        self.assertTrue(severe[0].rule_id.startswith("web-nuclei-"))


class TestWafAndDns(unittest.TestCase):
    def test_waf_detected(self):
        fs = PARSERS["wafw00f"](WAFW00F_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].rule_id, "web-waf-detected")

    def test_dns_records(self):
        fs = PARSERS["dnsrecon"](DNSRECON_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertTrue(all(f.rule_id == "web-dns-record" for f in fs))


class TestAttackParsers(unittest.TestCase):
    def test_sqlmap(self):
        fs = PARSERS["sqlmap"](SQLMAP_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].category, "injection")
        self.assertTrue(severity_ge(fs[0].severity, "critical"))

    def test_sqlmap_not_injectable_empty(self):
        self.assertEqual(PARSERS["sqlmap"](
            "[INFO] Parameter 'id' is not injectable", TARGET), [])

    def test_xsstrike(self):
        fs = PARSERS["xsstrike"](XSSSTRIKE_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertTrue(all(f.category == "xss" for f in fs))

    def test_commix(self):
        fs = PARSERS["commix"](COMMIX_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].rule_id, "web-commix-injectable")

    def test_hydra(self):
        fs = PARSERS["hydra"](HYDRA_SAMPLE, TARGET)
        self.assertTrue(fs)
        self.assertEqual(fs[0].rule_id, "web-hydra-credential")


class TestDispatch(unittest.TestCase):
    def test_unknown_parser_returns_empty(self):
        self.assertEqual(parse_output("nonexistent", "x", TARGET), [])

    def test_all_parsers_exist(self):
        from kali.tools import all_tools, TOOLS
        for name, spec in all_tools(attack=True):
            parser = spec.get("parser")
            self.assertIn(parser, PARSERS, f"parseur manquant : {parser}")

    def test_never_raises_on_weird_output(self):
        for parser in PARSERS.values():
            self.assertIsInstance(parser("X", TARGET), list)


if __name__ == "__main__":
    unittest.main()
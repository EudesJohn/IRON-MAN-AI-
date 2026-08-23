"""Tests de l'analyseur de qualité (scanner/quality_analyzer.py).

Couvre les métriques de fonction (accolades), les règles par-ligne, les
règles async/performance JS et les anti-faux-positifs (strings masquées,
config, Promise.all, littéraux).
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scanner.crawler import SourceFile
from scanner.quality_analyzer import QualityAnalyzer


def js(name="app.js"):
    return SourceFile(name, name, "javascript", "source")


sf = js  # alias : par défaut, un fichier JavaScript


def pysrc(name="app.py"):
    return SourceFile(name, name, "python", "python")


def analyze(sf_obj, content):
    return QualityAnalyzer().analyze(sf_obj, content)


def ids(findings):
    return [f.rule_id for f in findings]


class TestLongLine(unittest.TestCase):

    def test_triggers_on_long_non_comment_line(self):
        code = "const x = 1;\n" + "a" * 130 + "\nconst y = 2;\n"
        findings = analyze(sf(), code)
        self.assertIn("js-long-line", ids(findings))

    def test_skips_long_url_and_comment(self):
        code = "// " + "u" * 140 + "\n"
        code += 'const url = "https://' + "u" * 140 + '";\n'
        insights = analyze(sf(), code)
        self.assertNotIn("js-long-line", ids(insights))


class TestFunctionMetrics(unittest.TestCase):
    def test_function_too_long(self):
        body = "function big() {\n" + ("  const a = 1;\n" * 52) + "}\n"
        findings = analyze(sf(), body)
        self.assertIn("js-function-too-long", ids(findings))

    def test_short_function_ok(self):
        body = "function small() {\n  return 1;\n}\n"
        suggestions = analyze(sf(), body)
        self.assertNotIn("js-function-too-long", ids(suggestions))

    def test_high_cyclomatic(self):
        lines = ["function big(x) {"]
        lines += [f"  if (x{i}) {{ }}" for i in range(11)]
        lines.append("}")
        findings = analyze(sf(), "\n".join(lines) + "\n")
        self.assertIn("js-high-complexity", ids(findings))

    def test_deep_nesting(self):
        inner = "if (e%d) {" * 5 + "}" * 5
        body = "function f(a) {\n  " + inner + "\n}\n"
        findings = analyze(sf(), body)
        self.assertIn("js-deep-nesting", ids(findings))

    def test_too_many_params(self):
        body = "function f(a, b, c, d, e) { return 1; }\n"
        findings = analyze(sf(), body)
        self.assertIn("js-too-many-params", ids(findings))

    def test_if_block_not_counted_as_function(self):
        body = "if (x) {\n  return 1;\n}\n"
        findings = analyze(sf(), body)
        self.assertNotIn("js-function-too-long", ids(findings))


class TestLineRules(unittest.TestCase):
    def test_file_too_long(self):
        code = "\n".join("x = 0" for _ in range(505)) + "\n"
        findings = analyze(pysrc(), code)
        self.assertIn("py-file-too-long", ids(findings))

    def test_commented_out_code_python(self):
        code = "# if result != ok:\n#     print('erreur')\n#     return None\n"
        findings = analyze(pysrc(), code)
        self.assertIn("py-commented-out-code", ids(findings))

    def test_todo_comment_not_commented_code(self):
        code = "# TODO: refactoriser cette fonction\n"
        code += "# TODO: revoir le cache\n# TODO: tester le cas limite\n"
        findings = analyze(pysrc(), code)
        self.assertNotIn("py-commented-out-code", ids(findings))


class TestJSPerf(unittest.TestCase):
    def test_blocking_sync_io(self):
        code = "const fs = require('fs');\n"
        code += "function loadData() {\n  const d = fs.readFileSync('a.txt');\n"
        code += "  return d;\n}\n"
        findings = analyze(sf(), code)
        self.assertIn("perf-blocking-sync-io", ids(findings))

    def test_sync_io_in_config_functok_skip(self):
        code = "const fs = require('fs');\n"
        code += "function setup() {\n  const d = fs.readFileSync('a.txt');\n"
        code += "  return d;\n}\n"
        insights = analyze(sf(), code)
        self.assertNotIn("perf-blocking-sync-io", ids(insights))

    def test_sync_io_top_level_skip(self):
        code = "const fs = require('fs');\nconst d = fs.readFileSync('c.json');\n"
        insights = analyze(sf(), code)
        self.assertNotIn("perf-blocking-sync-io", ids(insights))

    def test_io_in_loop(self):
        code = "async function run(items) {\n"
        code += "  for (const item of items) {\n"
        code += "    const r = await fetch(item);\n"
        code += "  }\n"
        code += "}\n"
        findings = analyze(sf(), code)
        self.assertIn("perf-io-in-loop", ids(findings))

    def test_io_in_promise_all_skip(self):
        code = "async function run(items) {\n"
        code += "  await Promise.all(items.map(async (item) => {\n"
        code += "    const r = await fetch(item);\n"
        code += "    return r;\n"
        code += "  }));\n"
        code += "}\n"
        insights = analyze(sf(), code)
        self.assertNotIn("perf-io-in-loop", ids(insights))

    def test_quadratic_loop(self):
        code = "function find(a, b) {\n"
        code += "  for (const x of a) {\n    for (const y of b) {\n"
        code += "      if (x.id === y.id) { return x; }\n"
        code += "    }\n  }\n"
        code += "}\n"
        findings = analyze(sf(), code)
        self.assertIn("perf-quadratic-loop", ids(findings))

    def test_includes_literal_in_loop_not_quadratic(self):
        code = "function check(items) {\n"
        code += "  for (const x of items) {\n"
        code += "    if (ok.includes('x')) { return true; }\n"
        code += "  }\n"
        code += "}\n"
        insights = analyze(sf(), code)
        self.assertNotIn("perf-quadratic-loop", ids(insights))


class TestJSDebug(unittest.TestCase):
    def test_console_log(self):
        findings = analyze(sf(), "function f() {\n  console.log('hi');\n}\n")
        self.assertIn("js-no-debug-console", ids(findings))

    def test_console_in_string_skip(self):
        code = "const s = \"console.log('truc')\";\n"
        insights = analyze(sf(), code)
        self.assertNotIn("js-no-debug-console", ids(insights))

    def test_alert(self):
        findings = analyze(sf(), "function f() {\n  alert('hello');\n}\n")
        self.assertIn("js-no-alert", ids(findings))

    def test_deep_clone(self):
        code = "function copy(o) {\n  return JSON.parse(JSON.stringify(o));\n}\n"
        findings = analyze(sf(), code)
        self.assertIn("js-deep-clone-json", ids(findings))


class TestJSBlocks(unittest.TestCase):
    def test_loose_equality(self):
        findings = analyze(sf(), "if (a == b) {\n  return 1;\n}\n")
        self.assertIn("js-loose-equality", ids(findings))

    def test_strict_equality_ok(self):
        insights = analyze(sf(), "if (a === b) {\n  return 1;\n}\n")
        self.assertNotIn("js-loose-equality", ids(insights))

    def test_loose_equality_in_string_ignored(self):
        code = "const s = \"a == b\";\n"
        insights = analyze(sf(), code)
        self.assertNotIn("js-loose-equality", ids(insights))

    def test_redundant_boolean(self):
        findings = analyze(sf(), "if (x === true) {\n  return 1;\n}\n")
        self.assertIn("js-redundant-boolean", ids(findings))

    def test_empty_catch(self):
        code = "function f() {\n  try { } catch (e) { }\n}\n"
        findings = analyze(sf(), code)
        self.assertIn("js-empty-catch", ids(findings))

    def test_nonempty_catch_ok(self):
        code = "function f() {\n  try { } catch (e) { handle(e); }\n}\n"
        insights = analyze(sf(), code)
        self.assertNotIn("js-empty-catch", ids(insights))

    def test_else_after_return(self):
        code = "function f(x) {\n"
        code += "  if (x) { return 1; }\n  else { return 2; }\n"
        code += "}\n"
        findings = analyze(sf(), code)
        self.assertIn("js-else-after-return", ids(findings))

    def test_magic_number_conservative(self):
        code = "function f(x) {\n  if (x > 64000) { return 1; }\n}\n"
        findings = analyze(sf(), code)
        self.assertIn("js-magic-number", ids(findings))

    def test_skip_small_numbers_as_magic(self):
        code = "function f(x) {\n  if (x > 1) { return 1; }\n}\n"
        insights = analyze(sf(), code)
        self.assertNotIn("js-magic-number", ids(insights))


if __name__ == "__main__":
    unittest.main()
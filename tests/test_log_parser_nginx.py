import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
import io
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_parser_nginx import LogAnalyzer, parse_request

class JsonlTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer(
            use_remote=False,
            cache_path=Path("/tmp/does-not-exist.json"),
            collect_attacks=True,
        )

    ATTACK = ('10.0.0.5 - - [10/Oct/2023:13:55:37 +0000] '
              '"GET /?id=1\' UNION SELECT 1 HTTP/1.1" 200 1 "-" "sqlmap"\n')

    def _run(self):
        self.analyzer.process_line(self.ATTACK)
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.analyzer.report(as_jsonl=True)
        return buf.getvalue()

    def test_one_line_per_attack(self):
        out = self._run()
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(rec["ip"], "10.0.0.5")

    def test_no_array_brackets(self):
        self.assertFalse(self._run().strip().startswith("["))

    def test_ua_dash_becomes_null(self):
        self.analyzer.attacks = [{
            "ip": "1.1.1.1", "time": "10/Oct/2023:13:55:37 +0000",
            "method": "GET", "url": "/x", "protocol": "HTTP/1.1",
            "status": "200", "size": "1", "referer": "-", "user_agent": "-",
        }]
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.analyzer.report(as_jsonl=True)
        self.assertIn('"user_agent": null', buf.getvalue())

    def test_time_converted_to_utc(self):
        self.assertEqual(
            LogAnalyzer._parse_time("10/Oct/2023:13:55:37 +0300"),
            "2023-10-10T10:55:37Z",
        )

    def test_empty_attacks_gives_empty_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.analyzer.report(as_jsonl=True)
        self.assertEqual(buf.getvalue().strip(), "")

class ParseRequestTests(unittest.TestCase):
    def test_simple_request(self):
        method, url, protocol = parse_request("GET /index.html HTTP/1.1")
        self.assertEqual(method, "GET")
        self.assertEqual(url, "/index.html")
        self.assertEqual(protocol, "HTTP/1.1")

    def test_url_with_literal_space(self):
        method, url, protocol = parse_request(
            "GET /?id=1' UNION SELECT username,password FROM users-- HTTP/1.1"
        )
        self.assertEqual(method, "GET")
        self.assertEqual(url, "/?id=1' UNION SELECT username,password FROM users--")
        self.assertEqual(protocol, "HTTP/1.1")

    def test_request_without_protocol(self):
        method, url, protocol = parse_request("GET /foo/bar with spaces")
        self.assertEqual(method, "GET")
        self.assertEqual(url, "/foo/bar with spaces")
        self.assertEqual(protocol, "")

    def test_dash_request(self):
        self.assertEqual(parse_request("-"), ("", "", ""))

    def test_empty_request(self):
        self.assertEqual(parse_request(""), ("", "", ""))


class LogAnalyzerParsingTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer(use_remote=False, cache_path=Path("/tmp/does-not-exist.json"))

    def test_parse_line_regular(self):
        line = ('127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" '
                '200 1024 "-" "Mozilla/5.0"\n')
        parsed = self.analyzer.parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "127.0.0.1")
        self.assertEqual(parsed["url"], "/index.html")

    def test_sqli_with_literal_space_is_detected(self):
        line = ('10.0.0.5 - - [10/Oct/2023:13:55:37 +0000] '
                '"GET /?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" '
                '200 512 "-" "sqlmap/1.0"\n')
        parsed = self.analyzer.parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertTrue(self.analyzer.is_attack(parsed))

    def test_path_traversal_is_detected(self):
        line = ('10.0.0.5 - - [10/Oct/2023:13:55:38 +0000] "GET /../../etc/passwd HTTP/1.1" '
                '404 100 "-" "curl/7.0"\n')
        parsed = self.analyzer.parse_line(line)
        self.assertTrue(self.analyzer.is_attack(parsed))

    def test_clean_request_is_not_flagged(self):
        line = ('127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /about HTTP/1.1" '
                '200 200 "-" "Mozilla/5.0"\n')
        parsed = self.analyzer.parse_line(line)
        self.assertFalse(self.analyzer.is_attack(parsed))

    def test_double_encoded_payload_is_detected(self):
        line = ('192.168.1.1 - - [10/Oct/2023:13:55:39 +0000] '
                '"GET /page?x=%253Cscript%253E HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n')
        parsed = self.analyzer.parse_line(line)
        self.assertTrue(self.analyzer.is_attack(parsed))


class CrsRxExtractionTests(unittest.TestCase):
    def test_extract_pl1_rule_by_default(self):
        conf = '''
SecRule ARGS "@rx (?i:union\\s+select)" \\
    "id:942270,\\
    phase:2,\\
    tag:'paranoia-level/1',\\
    deny"
'''
        patterns = LogAnalyzer._extract_rx_patterns(conf)
        self.assertEqual(patterns, [r"(?i:union\s+select)"])

    def test_extract_ignores_action_block_content(self):
        conf = '''
SecRule REQUEST_URI "@rx \\.\\./\\.\\./" \\
    "id:930100,\\
    msg:'Path Traversal Attack',\\
    tag:'paranoia-level/1',\\
    phase:2"
'''
        patterns = LogAnalyzer._extract_rx_patterns(conf)
        self.assertEqual(patterns, [r"\.\./\.\./"])
        compiled = LogAnalyzer._compile_patterns(patterns)
        self.assertEqual(len(compiled), 1)
        self.assertTrue(compiled[0].search("/../../etc/passwd"))

    def test_extract_skips_non_rx_operators(self):
        conf = 'SecRule ARGS "@contains admin" "id:1,phase:2,tag:\'paranoia-level/1\'"'
        patterns = LogAnalyzer._extract_rx_patterns(conf)
        self.assertEqual(patterns, [])

    def test_pl2_rule_excluded_by_default(self):
        conf = '''
SecRule ARGS "@rx (?i)\\bxor\\b" \\
    "id:942120,\\
    phase:2,\\
    tag:'paranoia-level/2',\\
    deny"
'''
        self.assertEqual(LogAnalyzer._extract_rx_patterns(conf), [])
        self.assertEqual(LogAnalyzer._extract_rx_patterns(conf, max_paranoia_level=2), [r"(?i)\bxor\b"])

    def test_rule_without_paranoia_tag_is_skipped(self):
        conf = '''
SecRule ARGS "@rx (?i)union\\s+select" \\
    "id:999999,\\
    phase:2,\\
    deny"
'''
        self.assertEqual(LogAnalyzer._extract_rx_patterns(conf), [])

    def test_pl1_signature_does_not_flag_normal_browser_ua(self):
        conf = '''
SecRule REQUEST_COOKIES "@rx (?i)union.*?select.*?from" \\
    "id:942270,\\
    phase:2,\\
    tag:'paranoia-level/1',\\
    deny"
'''
        patterns = LogAnalyzer._compile_patterns(LogAnalyzer._extract_rx_patterns(conf))
        normal_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
        self.assertFalse(any(p.search(normal_ua) for p in patterns))


class CacheTests(unittest.TestCase):
    def test_cache_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "patterns_cache.json"
            analyzer = LogAnalyzer(use_remote=False, cache_path=cache_path, crs_ref="v4.0.0")
            patterns = analyzer._compile_patterns([r"union\s+select", r"\.\./"])
            analyzer._save_to_cache(patterns)

            loaded = analyzer._load_from_cache(allow_stale=False)
            self.assertIsNotNone(loaded)
            self.assertEqual({p.pattern for p in loaded}, {r"union\s+select", r"\.\./"})

    def test_cache_invalidated_on_ref_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "patterns_cache.json"
            payload = {
                "timestamp": time.time(),
                "crs_ref": "v3.3.0",
                "patterns": [r"union\s+select"],
            }
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

            analyzer = LogAnalyzer(use_remote=False, cache_path=cache_path, crs_ref="v4.0.0")
            loaded = analyzer._load_from_cache(allow_stale=True)
            self.assertIsNone(loaded)

    def test_cache_invalidated_on_paranoia_level_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "patterns_cache.json"
            payload = {
                "timestamp": time.time(),
                "crs_ref": "v4.0.0",
                "paranoia_level": 2,
                "patterns": [r"\bxor\b"],
            }
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

            analyzer = LogAnalyzer(use_remote=False, cache_path=cache_path, crs_ref="v4.0.0", paranoia_level=1)
            loaded = analyzer._load_from_cache(allow_stale=True)
            self.assertIsNone(loaded)

    def test_cache_invalidated_when_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "patterns_cache.json"
            payload = {
                "timestamp": time.time() - 2 * 24 * 60 * 60,
                "crs_ref": "v4.0.0",
                "paranoia_level": 1,
                "patterns": [r"union\s+select"],
            }
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

            analyzer = LogAnalyzer(use_remote=False, cache_path=cache_path, crs_ref="v4.0.0")
            loaded = analyzer._load_from_cache(allow_stale=False)
            self.assertIsNone(loaded)
            loaded_stale = analyzer._load_from_cache(allow_stale=True)
            self.assertIsNotNone(loaded_stale)


if __name__ == "__main__":
    unittest.main()

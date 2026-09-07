import re
import argparse
import sys
import json
import gzip
import time
import signal
import requests
from pathlib import Path
from urllib.parse import unquote
from collections import Counter

CRS_REF = "v4.0.0"
CRS_API_URL = "https://api.github.com/repos/coreruleset/coreruleset/contents/rules"
CRS_RAW_URL = "https://raw.githubusercontent.com/coreruleset/coreruleset"
CRS_FILE_RE = re.compile(r'^REQUEST-(93[0-4]|94[0-4])-[A-Z0-9\-]+\.conf$')
DEFAULT_CACHE_PATH = Path("patterns_cache.json")
DEFAULT_CACHE_TTL = 24 * 60 * 60
LINE_MATCH_TIMEOUT = 2
HTTP_METHOD_RE = re.compile(r'^[A-Z]+$')
HTTP_VERSION_RE = re.compile(r'^HTTP/\d(\.\d)?$', re.IGNORECASE)
LINE_CONTINUATION_RE = re.compile(r'\\\r?\n')
SECRULE_RX_RE = re.compile(
    r'SecRule\s+\S+\s+"@rx\s+((?:\\.|[^"])*)"\s+"((?:\\.|[^"])*)"', re.DOTALL
)
PARANOIA_TAG_RE = re.compile(r"paranoia-level/(\d)")
DEFAULT_MAX_PARANOIA_LEVEL = 1


class MatchTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise MatchTimeout()


def read_arg() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Поиск атак в access-логах nginx по regex-сигнатурам.")
    parser.add_argument("logfile", help="файл лога (поддерживается .gz)")
    parser.add_argument("--top", type=int, default=10, help="сколько IP показать в отчёте (по умолчанию 10)")
    parser.add_argument("--json", action="store_true", help="вывести отчёт в формате JSON")
    parser.add_argument("--no-remote", action="store_true",
                         help="не ходить в сеть за паттернами; использовать кэш (если есть) или встроенные правила")
    parser.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL,
                         help="время жизни кэша паттернов в секундах (по умолчанию 86400)")
    parser.add_argument("--crs-ref", default=CRS_REF,
                         help=f"git-тег/коммит coreruleset, из которого брать правила (по умолчанию {CRS_REF})")
    parser.add_argument("--paranoia-level", type=int, default=DEFAULT_MAX_PARANOIA_LEVEL, choices=[1, 2, 3, 4],
                         help="макс. paranoia level CRS-правил для загрузки (по умолчанию 1, как в самом CRS; "
                              "уровни 2-4 дают больше покрытия, но заметно больше ложных срабатываний)")
    args = parser.parse_args()
    return args


def parse_request(request):
    if not request or request == "-":
        return "", "", ""

    parts = request.split(" ")
    if len(parts) == 1:
        return parts[0], "", ""

    method = parts[0]
    if not HTTP_METHOD_RE.match(method):
        return "", request, ""

    if HTTP_VERSION_RE.match(parts[-1]) and len(parts) > 2:
        protocol = parts[-1]
        url = " ".join(parts[1:-1])
    else:
        protocol = ""
        url = " ".join(parts[1:])

    return method, url, protocol


class LogAnalyzer:
    def __init__(self, use_remote=True, cache_ttl=DEFAULT_CACHE_TTL, cache_path=DEFAULT_CACHE_PATH,
                 crs_ref=CRS_REF, paranoia_level=DEFAULT_MAX_PARANOIA_LEVEL):
        self.log_pattern = re.compile(
            r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
            r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        self.cache_path = cache_path
        self.cache_ttl = cache_ttl
        self.crs_ref = crs_ref
        self.paranoia_level = paranoia_level
        if self.paranoia_level > 1:
            print(
                f"Предупреждение: paranoia level {self.paranoia_level} в OWASP CRS документированно даёт много "
                f"ложных срабатываний на обычном трафике (короткие подстроки команд, апострофы, спецсимволы) — "
                f"без аномального скоринга, который есть в полноценном ModSecurity, это особенно заметно.",
                file=sys.stderr,
            )
        self.attack_patterns = self._load_patterns(use_remote=use_remote)
        self.counter = Counter()
        self._alarm_supported = hasattr(signal, "SIGALRM")

    def _load_patterns(self, use_remote=True):
        if use_remote:
            cached = self._load_from_cache(allow_stale=False)
            if cached is not None:
                print(f"{len(cached)} паттернов загружено из кэша.", file=sys.stderr)
                return cached

            patterns = self._load_remote_patterns()
            if patterns:
                print(f"{len(patterns)} паттернов загружено из OWASP CRS ({self.crs_ref}, "
                      f"paranoia level <= {self.paranoia_level}).", file=sys.stderr)
                self._save_to_cache(patterns)
                return patterns

            print("Ошибка: не удалось загрузить правила из coreruleset.", file=sys.stderr)

            stale = self._load_from_cache(allow_stale=True)
            if stale is not None:
                print(f"Используется устаревший кэш ({len(stale)} паттернов).", file=sys.stderr)
                return stale
        else:
            cached = self._load_from_cache(allow_stale=True)
            if cached is not None:
                print(f"{len(cached)} паттернов загружено из кэша (офлайн-режим).", file=sys.stderr)
                return cached

        print("Используются встроенные паттерны.", file=sys.stderr)
        return self._load_fallback_patterns()

    def _load_remote_patterns(self):
        try:
            listing = requests.get(
                CRS_API_URL,
                params={"ref": self.crs_ref},
                headers={"Accept": "application/vnd.github+json"},
                timeout=15,
            )
            listing.raise_for_status()
            entries = listing.json()
        except Exception as e:
            print(f"Ошибка сети при получении списка правил: {e}.", file=sys.stderr)
            return None

        rule_files = [
            entry["name"] for entry in entries
            if isinstance(entry, dict) and CRS_FILE_RE.match(entry.get("name", ""))
        ]
        if not rule_files:
            print("Не найдено ни одного файла правил в coreruleset.", file=sys.stderr)
            return None

        raw_regexes = []
        for name in rule_files:
            url = f"{CRS_RAW_URL}/{self.crs_ref}/rules/{name}"
            try:
                response = requests.get(url, timeout=15)
                response.raise_for_status()
            except Exception as e:
                print(f"Предупреждение: не удалось загрузить {name}: {e}", file=sys.stderr)
                continue
            raw_regexes.extend(self._extract_rx_patterns(response.text, self.paranoia_level))

        if not raw_regexes:
            return None

        return self._compile_patterns(raw_regexes)

    @staticmethod
    def _extract_rx_patterns(conf_text, max_paranoia_level=DEFAULT_MAX_PARANOIA_LEVEL):
        joined = LINE_CONTINUATION_RE.sub(" ", conf_text)
        patterns = []
        for m in SECRULE_RX_RE.finditer(joined):
            rx, action = m.group(1), m.group(2)
            if len(rx) <= 2:
                continue
            level_match = PARANOIA_TAG_RE.search(action)
            if not level_match or int(level_match.group(1)) > max_paranoia_level:
                continue
            patterns.append(rx)
        return patterns

    def _load_fallback_patterns(self):
        raw_regexes = [
            r'union\s+select',
            r'\s+or\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+',
            r'drop\s+table',
            r'sleep\s*\(',
            r'javascript:',
            r'<script',
            r'on\w+\s*=',
            r'\.\./',
            r'etc/passwd',
            r'system\s*\(',
            r'%00',
        ]
        return self._compile_patterns(raw_regexes)

    @staticmethod
    def _compile_patterns(raw_regexes):
        compiled = []
        seen = set()
        for regex in raw_regexes:
            if regex in seen:
                continue
            seen.add(regex)
            try:
                compiled.append(re.compile(regex, re.IGNORECASE))
            except re.error:
                continue
        return compiled

    def _save_to_cache(self, compiled_patterns):
        try:
            payload = {
                "timestamp": time.time(),
                "source": f"{CRS_RAW_URL}/{self.crs_ref}/rules",
                "crs_ref": self.crs_ref,
                "paranoia_level": self.paranoia_level,
                "patterns": [p.pattern for p in compiled_patterns],
            }
            self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as e:
            print(f"Предупреждение: не удалось сохранить кэш паттернов: {e}", file=sys.stderr)

    def _load_from_cache(self, allow_stale):
        if not self.cache_path.exists():
            return None
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        if payload.get("crs_ref") != self.crs_ref or payload.get("paranoia_level") != self.paranoia_level:
            return None

        age = time.time() - payload.get("timestamp", 0)
        if not allow_stale and age > self.cache_ttl:
            return None

        return self._compile_patterns(payload.get("patterns", []))

    def parse_line(self, line):
        m = self.log_pattern.match(line)
        if not m:
            return None

        method, url, protocol = parse_request(m.group("request"))

        return {
            "ip": m.group("ip"),
            "time": m.group("time"),
            "method": method,
            "url": url,
            "protocol": protocol,
            "status": m.group("status"),
            "size": m.group("size"),
            "referer": m.group("referer"),
            "user_agent": m.group("user_agent"),
        }

    @staticmethod
    def _decode_multi(value, max_passes=3):
        decoded = value
        for _ in range(max_passes):
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        return decoded

    def is_attack(self, parsed):
        candidates = (parsed.get("url", ""), parsed.get("referer", ""), parsed.get("user_agent", ""))
        for raw in candidates:
            decoded = self._decode_multi(raw)
            for attack_re in self.attack_patterns:
                if attack_re.search(decoded):
                    return True
        return False

    def _is_attack_with_timeout(self, parsed):
        if not self._alarm_supported:
            return self.is_attack(parsed)

        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(LINE_MATCH_TIMEOUT)
        try:
            return self.is_attack(parsed)
        except MatchTimeout:
            print(f"Предупреждение: тайм-аут при сопоставлении паттернов, строка пропущена "
                  f"(ip={parsed.get('ip')}).", file=sys.stderr)
            return False
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def process_line(self, line):
        parsed = self.parse_line(line)
        if parsed and self._is_attack_with_timeout(parsed):
            self.counter[parsed["ip"]] += 1

    def report(self, top_n=10, as_json=False):
        top_ips = self.counter.most_common(top_n)

        if as_json:
            print(json.dumps(
                [{"ip": ip, "count": count} for ip, count in top_ips],
                ensure_ascii=False,
                indent=2,
            ))
            return

        if not top_ips:
            print("Подозрительных запросов не обнаружено.")
            return

        print("Топ нарушителей:")
        for ip, count in top_ips:
            print(f"{ip} -> {count} попыток")


def _open_logfile(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def main():
    args = read_arg()
    analyzer = LogAnalyzer(
        use_remote=not args.no_remote,
        cache_ttl=args.cache_ttl,
        crs_ref=args.crs_ref,
        paranoia_level=args.paranoia_level,
    )

    try:
        with _open_logfile(args.logfile) as f:
            for line in f:
                analyzer.process_line(line)

    except FileNotFoundError:
        print(f"Ошибка: файл '{args.logfile}' не найден.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Ошибка: нет доступа к '{args.logfile}'.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Ошибка: '{args.logfile}' является директорией, а не файлом.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка чтения '{args.logfile}': {e}", file=sys.stderr)
        sys.exit(1)

    analyzer.report(top_n=args.top, as_json=args.json)


if __name__ == "__main__":
    main()

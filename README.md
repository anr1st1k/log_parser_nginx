# log_parser_nginx

CLI-утилита для поиска атак в access-логах nginx по regex-сигнатурам (SQLi, XSS, path traversal и др.), с загрузкой правил из официального репозитория OWASP Core Rule Set и кэшированием.

## Примеры

```bash
# Разбор лога, топ-10 IP по умолчанию
python log_parser_nginx.py access.log

# Топ-20 IP
python log_parser_nginx.py --top 20 access.log

# Вывод в JSON
python log_parser_nginx.py --json access.log

# Без обращения к сети (кэш или встроенные паттерны)
python log_parser_nginx.py --no-remote access.log

# Ротированный (сжатый) лог
python log_parser_nginx.py access.log.1.gz

# Другая версия/тег coreruleset
python log_parser_nginx.py --crs-ref v4.6.0 access.log

# Более агрессивный уровень правил CRS (больше покрытия, но больше false positive)
python log_parser_nginx.py --paranoia-level 2 access.log
```

## Требования

Python 3.9 или новее, `requests`. Устанавливаются из `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Установка и запуск

```bash
git clone https://github.com/anr1st1k/log_parser_nginx.git
cd log_parser_nginx
python log_parser_nginx.py путь/к/access.log
```

## Принцип работы

Утилита построчно разбирает access-лог формата nginx (`combined`). Поле запроса (`"METHOD URL PROTOCOL"`) разбирается отдельно: метод - первый токен, протокол - последний токен, между ними, - URL, включая случайные буквальные пробелы.

URL, Referer и User-Agent декодируются в несколько проходов и сверяются с набором regex-сигнатур атак.

Сигнатуры по умолчанию собираются из **официального репозитория [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)** (OWASP CRS). Утилита:

1. запрашивает список файлов `rules/REQUEST-93x-*.conf` и `rules/REQUEST-94x-*.conf` (LFI/RFI/RCE/PHP/XSS/SQLi/сессии/Java) на зафиксированном теге;
2. скачивает каждый файл и извлекает аргументы оператора `@rx` из директив `SecRule` (формат ModSecurity/SecLang);
3. компилирует извлечённые выражения как Python `re` и отбрасывает те, что не компилируются.

Правила кэшируются локально (`patterns_cache.json`, сутки по умолчанию, привязка к `--crs-ref`) и обновляются при смене тега. Если сеть недоступна и кэша нет - используется встроенный минимальный набор паттернов. Флаг `--no-remote` полностью отключает сетевые запросы.

Сопоставление каждой строки с паттернами ограничено тайм-аутом (по умолчанию 2 секунды, на платформах без `SIGALRM` тайм-аут не применяется).

По итогам разбора выводится список IP-адресов с наибольшим числом подозрительных запросов - в текстовом виде или в JSON (`--json`).

## Тесты

```bash
python -m unittest discover -s tests
```

## Docker

```bash
# Сборка образа
docker build -t log-parser .

# Запуск: монтируем папку с логами
docker run --rm -v "$PWD/logs:/logs" log-parser /logs/access.log --top 20

# JSON-вывод
docker run --rm -v "$PWD/logs:/logs" log-parser /logs/access.log --json

## Лицензия

MIT — подробности в [LICENSE](LICENSE).

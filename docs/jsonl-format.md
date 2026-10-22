# Формат jsonl

|Поле|Тип|Пример|Обязательно|Описание|
|:--:|:-:|:----:|:---------:|:------:|
|time|str|"2026-10-22T07:00:00Z"|да|время в ISO 8601, UTC|
|ip|str|"192.168.1.1"|да|IP источника|
|method|str|"GET"|да|HTTP-метод|
|protocol|str\|null|"HTTP/1.1"|нет|null если нет|
|url|str|"/api/v1/users/42"|да|$request_uri сырой|
|status|str|"200"|да|код ответа|
|user_agent|str\|null|"curl/8.4.0"|нет|null если "-"|

## Правила

- В JSONL все строки лога, которые распарсились. Не распарсилось - пропуск.
- time - UTC, до секунд.
- url сырой, декодирование только для детекта.
- protocol и user_agent - null если нет, не "".

## Пример строки

```json
{"time": "2026-10-22T07:00:00Z", "ip": "192.0.2.5", "method": "GET", "protocol": "HTTP/1.1", "url": "/api/v1/users/42", "status": "200", "user_agent": "curl/8.4.0"}

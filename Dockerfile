FROM python:3.11-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app log_parser_nginx.py .

USER app
WORKDIR /home/app

ENTRYPOINT ["python", "/app/log_parser_nginx.py"]

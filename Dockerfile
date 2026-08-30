FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chromium headless requis par pytr (resolution du WAF Trade Republic)
RUN playwright install --with-deps chromium

COPY . .

VOLUME ["/app/data"]

EXPOSE 5000

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "1"]

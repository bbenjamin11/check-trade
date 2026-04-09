FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ARG PIN_APP
ARG FLASK_SECRET_KEY

ENV PIN_APP=$PIN_APP
ENV FLASK_SECRET_KEY=$FLASK_SECRET_KEY

EXPOSE 5000

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "2"]

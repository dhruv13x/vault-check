FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -e '.[db,security,aws,dev]'

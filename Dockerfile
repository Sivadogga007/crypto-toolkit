# Dockerfile for Zero-Dependency Cryptanalysis Toolkit
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir pytest hypothesis

ENTRYPOINT ["python3", "-m", "crypto_toolkit.cli"]

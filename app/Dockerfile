# Intentionally insecure Dockerfile (container + IaC scanning demo):
# outdated base image with known OS CVEs, ADD instead of COPY, secret in ENV,
# SSH port exposed, no HEALTHCHECK, runs as root
FROM python:3.9.0-slim-buster
ADD . /app
WORKDIR /app
RUN pip install --upgrade pip && pip install -r requirements.txt
ENV DB_PASSWORD=admin123
EXPOSE 5000 22
CMD python server.py

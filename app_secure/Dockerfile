# Hardened Dockerfile: slim pinned base, non-root user, no secrets, HEALTHCHECK
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_HOST=0.0.0.0 APP_PORT=5000
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# copy only the application files, owned by root so the app user cannot modify them
COPY server.py db.py ./
COPY templates ./templates
USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"
CMD ["python", "server.py"]

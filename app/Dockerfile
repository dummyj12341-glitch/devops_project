# Intentionally insecure Dockerfile (for IaC / misconfiguration scanning demo)
FROM python:latest
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENV DB_PASSWORD=admin123
EXPOSE 5000 22
CMD python server.py

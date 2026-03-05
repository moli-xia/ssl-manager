FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl openssl socat \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data

ENV PORT=8080
ENV AUTO_RENEW=1
ENV DATA_DIR=/data

VOLUME ["/data"]

EXPOSE 8080

CMD ["python3", "/app/app.py"]

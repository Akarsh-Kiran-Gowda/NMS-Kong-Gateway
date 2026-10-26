#!/usr/bin/env bash
# Self-signed TLS cert for Kong (dev only). Idempotent.
cd "$(dirname "$0")/.."
[ -f certs/server.crt ] && exit 0
mkdir -p certs
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

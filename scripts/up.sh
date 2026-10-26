#!/usr/bin/env bash
# Start backend+Keycloak, wait for the realm, render kong.yml, then start Kong.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/gen_cert.sh
docker compose up -d --build nms-backend keycloak
until curl -sf http://localhost:8080/realms/nms >/dev/null; do sleep 3; done
python scripts/gen_kong_config.py
docker compose up -d --force-recreate kong
docker compose up -d prometheus grafana
until curl -sk -o /dev/null https://localhost:8443/; do sleep 2; done
echo "stack up"

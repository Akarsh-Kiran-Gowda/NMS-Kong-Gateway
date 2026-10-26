\# Secure API Gateway for NMS Northbound Interfaces



\## Goal

Demonstrate API security (authentication, authorization, rate limiting,

transport security, observability) in front of a mock NMS northbound interface.



\## Stack

\- Gateway: Kong OSS (DB-less, declarative kong.yml), pinned image version

\- IdP: Keycloak (OAuth2/OIDC, client\_credentials grant, imported realm JSON)

\- Backend: FastAPI mock NMS with /alarms, /devices, /performance, /config

\- Observability: Prometheus + Grafana

\- Later: NGINX variant (auth\_request or OpenResty) for comparison

\- Orchestration: Docker Compose



\## OAuth2 clients

\- monitoring-app: scopes alarms:read, performance:read; 20 req/min... (higher limit)

\- inventory-sync: scope devices:read

\- provisioning-system: scope config:write; strict rate limit; IP-restricted



\## Required behaviors

\- No token -> 401; wrong scope -> 403; over limit -> 429; valid -> 200

\- TLS termination, request size limit, allowed methods per route

\- Dashboard showing allowed vs blocked traffic



\## Rules

\- Work in phases; run and verify each phase before the next, show real curl output

\- Pin all image versions; secrets in .env (gitignored), provide .env.example

\- Explain each config file briefly after writing it

\- Commit after each working phase

\- Write automated tests (pytest or demo.sh) covering 200/401/403/429


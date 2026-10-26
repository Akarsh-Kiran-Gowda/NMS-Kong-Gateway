_format_version: "3.0"
services:
  - name: alarms
    url: http://nms-backend:8000
    routes:
      - name: alarms-route
        paths: ["/alarms"]
        methods: ["GET"]
        strip_path: false
        protocols: ["https"]
    plugins:
      - name: post-function
        config:
          access:
            - |
              local cjson = require "cjson.safe"
              local auth = kong.request.get_header("authorization") or ""
              local p = auth:match("^[Bb]earer%s+[^.]+%.([^.]+)%.")
              local claims
              if p then
                p = p:gsub("-", "+"):gsub("_", "/")
                p = p .. string.rep("=", (4 - #p % 4) % 4)
                local raw = ngx.decode_base64(p)
                claims = raw and cjson.decode(raw)
              end
              local ok = false
              if claims and type(claims.scope) == "string" then
                for s in claims.scope:gmatch("%S+") do
                  if s == "alarms:read" then ok = true end
                end
              end
              if not ok then
                return kong.response.exit(403, { message = "insufficient scope, requires alarms:read" })
              end
  - name: performance
    url: http://nms-backend:8000
    routes:
      - name: performance-route
        paths: ["/performance"]
        methods: ["GET"]
        strip_path: false
        protocols: ["https"]
    plugins:
      - name: post-function
        config:
          access:
            - |
              local cjson = require "cjson.safe"
              local auth = kong.request.get_header("authorization") or ""
              local p = auth:match("^[Bb]earer%s+[^.]+%.([^.]+)%.")
              local claims
              if p then
                p = p:gsub("-", "+"):gsub("_", "/")
                p = p .. string.rep("=", (4 - #p % 4) % 4)
                local raw = ngx.decode_base64(p)
                claims = raw and cjson.decode(raw)
              end
              local ok = false
              if claims and type(claims.scope) == "string" then
                for s in claims.scope:gmatch("%S+") do
                  if s == "performance:read" then ok = true end
                end
              end
              if not ok then
                return kong.response.exit(403, { message = "insufficient scope, requires performance:read" })
              end
  - name: devices
    url: http://nms-backend:8000
    routes:
      - name: devices-route
        paths: ["/devices"]
        methods: ["GET"]
        strip_path: false
        protocols: ["https"]
    plugins:
      - name: post-function
        config:
          access:
            - |
              local cjson = require "cjson.safe"
              local auth = kong.request.get_header("authorization") or ""
              local p = auth:match("^[Bb]earer%s+[^.]+%.([^.]+)%.")
              local claims
              if p then
                p = p:gsub("-", "+"):gsub("_", "/")
                p = p .. string.rep("=", (4 - #p % 4) % 4)
                local raw = ngx.decode_base64(p)
                claims = raw and cjson.decode(raw)
              end
              local ok = false
              if claims and type(claims.scope) == "string" then
                for s in claims.scope:gmatch("%S+") do
                  if s == "devices:read" then ok = true end
                end
              end
              if not ok then
                return kong.response.exit(403, { message = "insufficient scope, requires devices:read" })
              end
  - name: config
    url: http://nms-backend:8000
    routes:
      - name: config-route
        paths: ["/config"]
        methods: ["PUT"]
        strip_path: false
        protocols: ["https"]
    plugins:
      # Runs before auth (priority 3000), so a blocked IP is refused even with a valid token.
      - name: ip-restriction
        config:
          allow: ["172.16.0.0/12"]
          status: 403
          message: "source IP not allowed for provisioning"
      - name: post-function
        config:
          access:
            - |
              local cjson = require "cjson.safe"
              local auth = kong.request.get_header("authorization") or ""
              local p = auth:match("^[Bb]earer%s+[^.]+%.([^.]+)%.")
              local claims
              if p then
                p = p:gsub("-", "+"):gsub("_", "/")
                p = p .. string.rep("=", (4 - #p % 4) % 4)
                local raw = ngx.decode_base64(p)
                claims = raw and cjson.decode(raw)
              end
              local ok = false
              if claims and type(claims.scope) == "string" then
                for s in claims.scope:gmatch("%S+") do
                  if s == "config:write" then ok = true end
                end
              end
              if not ok then
                return kong.response.exit(403, { message = "insufficient scope, requires config:write" })
              end

# One consumer per OAuth2 client: jwt key_claim_name=azp maps the token's
# authorized party (client id) to the consumer; all share Keycloak's realm key.
consumers:
  - username: monitoring-app
    jwt_secrets:
      - key: monitoring-app
        algorithm: RS256
        rsa_public_key: |
__RSA_PUBLIC_KEY__
  - username: inventory-sync
    jwt_secrets:
      - key: inventory-sync
        algorithm: RS256
        rsa_public_key: |
__RSA_PUBLIC_KEY__
  - username: provisioning-system
    jwt_secrets:
      - key: provisioning-system
        algorithm: RS256
        rsa_public_key: |
__RSA_PUBLIC_KEY__

plugins:
  - name: prometheus
    config:
      per_consumer: true
      status_code_metrics: true
  - name: request-size-limiting
    config:
      allowed_payload_size: 10
      size_unit: kilobytes
  - name: jwt
    config:
      key_claim_name: azp
      claims_to_verify: [exp]
  - name: rate-limiting
    consumer: monitoring-app
    config:
      minute: 20
      policy: local
      limit_by: consumer
      error_code: 429
  - name: rate-limiting
    consumer: inventory-sync
    config:
      minute: 10
      policy: local
      limit_by: consumer
      error_code: 429
  - name: rate-limiting
    consumer: provisioning-system
    config:
      minute: 3
      policy: local
      limit_by: consumer
      error_code: 429

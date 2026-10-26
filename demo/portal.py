"""Demo portal: serves a click-through page and makes the gateway calls server-side
(fetches client tokens from Keycloak, so no secrets or CORS in the browser). Run: python demo/portal.py"""
import json, ssl, time, urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import attacks  # demo/attacks.py

ROOT = Path(__file__).resolve().parent.parent
ENV = dict(l.strip().split("=", 1) for l in (ROOT / ".env").read_text().splitlines() if "=" in l)
SECRETS = {"monitoring-app": ENV["MONITORING_APP_SECRET"], "inventory-sync": ENV["INVENTORY_SYNC_SECRET"],
           "provisioning-system": ENV["PROVISIONING_SYSTEM_SECRET"]}
TOKEN_URL = "http://localhost:8080/realms/nms/protocol/openid-connect/token"
GW = "https://localhost:8443"
CTX = ssl.create_default_context(cafile=str(ROOT / "certs" / "server.crt"))
_cache = {}


def token(client):
    t, exp = _cache.get(client, (None, 0))
    if time.time() > exp:
        d = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client,
                                    "client_secret": SECRETS[client]}).encode()
        r = json.load(urllib.request.urlopen(TOKEN_URL, d))
        t, exp = r["access_token"], time.time() + r["expires_in"] - 20
        _cache[client] = (t, exp)
    return t


def call(client, path, method, xff=None, big=False):
    h = {"Content-Type": "application/json"}
    if xff:
        h["X-Forwarded-For"] = xff
    if client != "none":
        h["Authorization"] = "Bearer " + token(client)
    req = urllib.request.Request(GW + path, method=method, headers=h, data=b"x" * 20000 if big else b'{"demo":1}' if method == "PUT" else None)
    try:
        r = urllib.request.urlopen(req, context=CTX)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            body, ctype, code = (Path(__file__).parent / "index.html").read_bytes(), "text/html", 200
        elif u.path == "/call":
            q = urllib.parse.parse_qs(u.query)
            code_, text = call(q["client"][0], q["path"][0], q["method"][0], q.get("xff", [None])[0], "big" in q)
            body, ctype, code = json.dumps({"status": code_, "body": text}).encode(), "application/json", 200
        elif u.path == "/attacks":
            body, ctype, code = json.dumps(attacks.run_all()).encode(), "application/json", 200
        else:
            body, ctype, code = b"", "text/plain", 404
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers(); self.wfile.write(body)


print("Demo portal on http://localhost:9000")
ThreadingHTTPServer(("127.0.0.1", 9000), H).serve_forever()

"""Attack demos: each forged/abusive request must be rejected by the gateway.
Used by tests/test_attacks.py, scripts/attack_demo.py and the demo portal."""
import base64, hashlib, hmac, json, subprocess, time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent.parent
GW = "https://localhost:8443"
KC = "http://localhost:8080"
CERT = str(ROOT / "certs" / "server.crt")
ENV = dict(l.strip().split("=", 1) for l in (ROOT / ".env").read_text().splitlines() if "=" in l)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_parts(token):
    h, p, s = token.split(".")
    return json.loads(unb64(h)), json.loads(unb64(p)), s


def build(header, claims, sig=b""):
    return f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}.{b64(sig)}"


def get_token(client="monitoring-app", secret_var="MONITORING_APP_SECRET"):
    r = requests.post(f"{KC}/realms/nms/protocol/openid-connect/token", data={
        "grant_type": "client_credentials", "client_id": client, "client_secret": ENV[secret_var]})
    r.raise_for_status()
    return r.json()["access_token"]


def call(token=None, path="/alarms", method="GET", **kw):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.request(method, GW + path, headers=h, verify=CERT, **kw).status_code


def forged_claims(**over):
    _, claims, _ = jwt_parts(get_token())
    now = int(time.time())
    claims.update(iat=now, exp=now + 300, **over)
    return claims


# ---- attacks: each returns the observed outcome ----
def tampered_signature():
    h, p, s = get_token().split(".")
    return call(f"{h}.{p}.{s[:-4]}AAAA")


def scope_escalation():
    """Valid signature, but payload edited to grant config:write."""
    h, p, s = get_token().split(".")
    claims = json.loads(unb64(p))
    claims["scope"] += " config:write"
    return call(f"{h}.{b64(json.dumps(claims).encode())}.{s}", "/config", "PUT", json={"x": 1})


def wrong_key():
    """Perfectly formed RS256 token signed with the attacker's own key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    head = {"alg": "RS256", "typ": "JWT"}
    claims = forged_claims()
    signing_input = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(claims).encode())}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return call(f"{signing_input.decode()}.{b64(sig)}")


def alg_none():
    return call(build({"alg": "none", "typ": "JWT"}, forged_claims()) )


def hs256_key_confusion():
    """Classic: sign with HS256 using the server's *public* key as the HMAC secret."""
    pub = requests.get(f"{KC}/realms/nms").json()["public_key"]
    pem = ("-----BEGIN PUBLIC KEY-----\n" + pub + "\n-----END PUBLIC KEY-----\n").encode()
    si = f"{b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())}.{b64(json.dumps(forged_claims()).encode())}"
    sig = hmac.new(pem, si.encode(), hashlib.sha256).digest()
    return call(f"{si}.{b64(sig)}")


def expired_token():
    """Real Keycloak-signed token that has genuinely expired (realm lifespan briefly set to 1s)."""
    adm = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": ENV["KEYCLOAK_ADMIN"],
        "password": ENV["KEYCLOAK_ADMIN_PASSWORD"]}).json()["access_token"]
    hdr = {"Authorization": f"Bearer {adm}"}
    set_life = lambda n: requests.put(f"{KC}/admin/realms/nms", headers=hdr, json={"accessTokenLifespan": n}).raise_for_status()
    set_life(1)
    try:
        token = get_token()
    finally:
        set_life(300)
    time.sleep(2.5)
    return call(token)


def oversized_payload():
    return call(get_token(), "/alarms", data="x" * 20_000)


def http_downgrade():
    return requests.get("http://localhost:8000/alarms").status_code


def hidden_backend_docs():
    """FastAPI's /docs and /openapi.json exist on the backend but must not be routable via the gateway."""
    t = get_token()
    return (call(t, "/docs"), call(t, "/openapi.json"))


def direct_backend_bypass():
    """Backend has no published port and sits on a network only Kong shares."""
    cid = subprocess.run(["docker", "compose", "ps", "-q", "nms-backend"], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    ports = json.loads(subprocess.run(["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", cid],
                                      capture_output=True, text=True).stdout)
    published = any(ports.values())
    # Another container on the normal network (prometheus) tries to reach the backend directly.
    r = subprocess.run(["docker", "compose", "exec", "-T", "prometheus", "wget", "-T", "3", "-q", "-O-",
                        "http://nms-backend:8000/alarms"], cwd=ROOT, capture_output=True, text=True)
    return "unreachable" if (not published and r.returncode != 0) else "REACHED BACKEND"


ATTACKS = [
    ("Tampered JWT signature", tampered_signature, 401),
    ("Payload edited to add config:write scope", scope_escalation, 401),
    ("Token signed with attacker's own RSA key", wrong_key, 401),
    ("alg=none (unsigned) token", alg_none, 401),
    ("HS256 key-confusion (public key as HMAC secret)", hs256_key_confusion, 401),
    ("Genuinely expired token", expired_token, 401),
    ("Oversized payload (20 KB, limit 10 KB)", oversized_payload, 413),
    ("Plain HTTP downgrade", http_downgrade, 426),
    ("Backend /docs and /openapi.json via gateway", hidden_backend_docs, (404, 404)),
    ("Direct-to-backend bypass", direct_backend_bypass, "unreachable"),
]


def run_all():
    out = []
    for name, fn, expected in ATTACKS:
        got = fn()
        out.append({"name": name, "expected": expected, "got": got, "blocked": got == expected})
    return out

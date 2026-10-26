"""End-to-end gateway tests: 200 / 401 / 403 / 429 through Kong with real Keycloak tokens."""
import time
from pathlib import Path

import pytest
import requests

GW = "https://localhost:8443"
CERT = str(Path(__file__).resolve().parent.parent / "certs" / "server.crt")
TOKEN_URL = "http://localhost:8080/realms/nms/protocol/openid-connect/token"
LIMITS = {"monitoring-app": 20, "inventory-sync": 10, "provisioning-system": 3}
SECRET_VARS = {
    "monitoring-app": "MONITORING_APP_SECRET",
    "inventory-sync": "INVENTORY_SYNC_SECRET",
    "provisioning-system": "PROVISIONING_SYSTEM_SECRET",
}


def _env():
    path = Path(__file__).resolve().parent.parent / ".env"
    return dict(l.strip().split("=", 1) for l in path.read_text().splitlines() if "=" in l)


def _token(client):
    r = requests.post(TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": client,
        "client_secret": _env()[SECRET_VARS[client]],
    })
    r.raise_for_status()
    return r.json()["access_token"]


def _get(path, client=None, method="GET", token=None, headers=None, data=None):
    headers = dict(headers or {})
    token = token or (_token(client) if client else None)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    kw = {"data": data} if data is not None else {"json": {"ntp": "1.1.1.1"}} if method == "PUT" else {}
    return requests.request(method, GW + path, headers=headers, verify=CERT, **kw)


def _fresh_minute():
    """Rate-limit windows are per wall-clock minute; start at the beginning of one."""
    s = time.time() % 60
    time.sleep(60 - s + 0.5)


@pytest.fixture(scope="session", autouse=True)
def clean_windows():
    # Start from a fresh minute so counters from a previous run don't leak in.
    time.sleep(60 - time.time() % 60 + 0.5)


# ---- 200 ----
@pytest.mark.parametrize("client,path,method", [
    ("monitoring-app", "/alarms", "GET"),
    ("monitoring-app", "/performance", "GET"),
    ("inventory-sync", "/devices", "GET"),
    ("provisioning-system", "/config", "PUT"),
])
def test_valid_token_correct_scope_200(client, path, method):
    assert _get(path, client, method).status_code == 200


# ---- 401 ----
@pytest.mark.parametrize("path", ["/alarms", "/devices", "/performance"])
def test_no_token_401(path):
    assert _get(path).status_code == 401


def test_garbage_token_401():
    assert _get("/alarms", token="not.a.jwt").status_code == 401


def test_tampered_token_401():
    t = _token("monitoring-app")
    head, body, sig = t.split(".")
    bad = f"{head}.{body}.{sig[:-4]}AAAA"
    assert _get("/alarms", token=bad).status_code == 401


# ---- 403 ----
@pytest.mark.parametrize("client,path,method", [
    ("inventory-sync", "/alarms", "GET"),
    ("monitoring-app", "/devices", "GET"),
    ("monitoring-app", "/config", "PUT"),
    ("provisioning-system", "/performance", "GET"),
])
def test_wrong_scope_403(client, path, method):
    assert _get(path, client, method).status_code == 403


# ---- method allow-list: a method not listed on the route doesn't match it (Kong 404) ----
def test_disallowed_method_not_routed():
    assert _get("/alarms", "monitoring-app", "DELETE").status_code == 404


# ---- transport / request hardening ----
def test_plain_http_refused_426():
    r = requests.get("http://localhost:8000/alarms")
    assert r.status_code == 426


def test_tls_certificate_verifies_against_our_cert():
    assert requests.get(GW + "/alarms", verify=CERT).status_code == 401  # TLS ok, just unauthenticated


def test_oversized_body_413():
    assert _get("/alarms", "monitoring-app", data="x" * 20_000).status_code == 413


def test_provisioning_blocked_from_other_ip_403():
    r = _get("/config", "provisioning-system", "PUT", headers={"X-Forwarded-For": "203.0.113.9"})
    assert r.status_code == 403 and "IP" in r.text


def test_provisioning_allowed_from_internal_ip():
    r = _get("/config", "provisioning-system", "PUT", headers={"X-Forwarded-For": "172.20.0.5"})
    assert r.status_code == 200


# ---- 429 (keep last: exhausts buckets for the current minute) ----
def test_over_limit_429_and_limits_are_per_client():
    _fresh_minute()  # one fresh window: earlier tests already spent some of this minute's budget
    for client, path, method in [("provisioning-system", "/config", "PUT"), ("monitoring-app", "/alarms", "GET")]:
        token = _token(client)
        codes = [_get(path, token=token, method=method).status_code for _ in range(LIMITS[client] + 1)]
        assert codes[:-1] == [200] * LIMITS[client], client
        assert codes[-1] == 429, client
    # both of those are exhausted; inventory-sync's bucket is untouched
    assert _get("/devices", "inventory-sync").status_code == 200

"""Render kong/kong.yml from kong.yml.tpl using Keycloak's realm signing key."""
import json, textwrap, urllib.request
from pathlib import Path

root = Path(__file__).resolve().parent.parent
realm = json.load(urllib.request.urlopen("http://localhost:8080/realms/nms"))
b64 = realm["public_key"]
pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END PUBLIC KEY-----"
block = "\n".join(" " * 10 + l for l in pem.splitlines())
tpl = (root / "kong" / "kong.yml.tpl").read_text()
(root / "kong" / "kong.yml").write_text(tpl.replace("__RSA_PUBLIC_KEY__", block))
print("wrote kong/kong.yml")

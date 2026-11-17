"""keys/의 인증서·키로 .well-known JSON과 security.txt를 만든다."""
import base64, datetime as dt, json, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

HERE = pathlib.Path(__file__).parent
PORTS = {"site": 18492, "site-broken": 18493}
PKG = "example.lab.shop"


def fp(path):  # 인증서 DER의 SHA-256, "AA:BB:..." 형식 (keytool -list -v 와 같은 모양)
    c = x509.load_pem_x509_certificate((HERE / path).read_bytes())
    return ":".join(f"{b:02X}" for b in c.fingerprint(hashes.SHA256()))


def b64u(i):
    return base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()


key = serialization.load_pem_private_key((HERE / "keys/jwt-signing.key").read_bytes(), None)
n = key.public_key().public_numbers()
jwk_pub = {"kty": "EC", "crv": "P-256", "x": b64u(n.x), "y": b64u(n.y),
           "use": "sig", "alg": "ES256", "kid": "FAKE-2026-10"}


def assetlinks(f):
    return [{"relation": ["delegate_permission/common.handle_all_urls",
                          "delegate_permission/common.get_login_creds"],
             "target": {"namespace": "android_app", "package_name": PKG,
                        "sha256_cert_fingerprints": [f]}}]


aasa = {"applinks": {"details": [{"appIDs": ["FAKETEAM01.example.lab.shop"],
                                  "components": [{"/": "/orders/*"}, {"/": "/admin/*", "exclude": True}]}]},
        "webcredentials": {"apps": ["FAKETEAM01.example.lab.shop"]}}

def oidc(port):
    ISSUER = f"https://localhost:{port}"
    return {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/oauth2/authorize",
            "token_endpoint": ISSUER + "/oauth2/token", "jwks_uri": ISSUER + "/.well-known/jwks.json",
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"]}

webauthn_ro = {"origins": ["https://shop.lab.example", "https://shop.lab.example.co.kr", "https://shop-pay.lab.example"]}

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def sectxt(expires, port):
    return ("# FAKE lab security.txt (RFC 9116)\n"
            "Contact: mailto:security@shop.lab.example\n"
            f"Expires: {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
            "Preferred-Languages: ko, en\n"
            f"Canonical: https://localhost:{port}/.well-known/security.txt\n"
            "Policy: https://shop.lab.example/security/policy\n")


def write(d, name, obj):
    p = HERE / d / ".well-known" / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


good, bad = "site", "site-broken"
write(good, "assetlinks.json", assetlinks(fp("keys/app-signing.crt")))
write(bad, "assetlinks.json", assetlinks(fp("keys/debug-signing.crt")))  # 디버그 키 지문을 올린 실수
for d in (good, bad):
    write(d, "apple-app-site-association", aasa)
    write(d, "openid-configuration", oidc(PORTS[d]))
    write(d, "webauthn", webauthn_ro)
write(good, "jwks.json", {"keys": [jwk_pub]})
priv_d = key.private_numbers().private_value
write(bad, "jwks.json", {"keys": [dict(jwk_pub, d=b64u(priv_d))]})  # 개인키 값 d가 섞인 사고
write(good, "security.txt", sectxt(now + dt.timedelta(days=180), 18492))
write(bad, "security.txt", sectxt(now - dt.timedelta(days=3), 18493))       # 만료된 security.txt
# site-broken은 AASA를 text/plain으로 내보낸다(server.py가 이 파일을 읽는다)
(HERE / bad / "_content_types.json").write_text(json.dumps({"apple-app-site-association": "text/plain"}))

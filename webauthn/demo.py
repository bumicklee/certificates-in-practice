"""30편 실습: 등록·로그인 성공, 그리고 피싱 출처에서의 실패 네 가지."""
import hashlib, json, sys

import httpx

from soft_authenticator import Browser, SoftAuthenticator, assertion_json, b64u, unb64u

SERVER = "http://127.0.0.1:18490"
REAL = "http://localhost:18490"
PHISH = "http://shop-login.lab.example"
USER = "alice@shop.lab.example"
http = httpx.Client(base_url=SERVER, timeout=5)


def post(path, body):
    r = http.post(path, json=body)
    return r.status_code, r.json()


def show(title, status, body):
    print(f"  서버 응답: HTTP {status} {json.dumps(body, ensure_ascii=False)}")


auth = SoftAuthenticator()
real = Browser(auth, REAL)
phish = Browser(auth, PHISH)

print("[1] 진짜 출처에서 등록", REAL)
opts = post("/register/options", {"user_name": USER})[1]
print("  options: rp.id =", opts["rp"]["id"], "| attestation =", opts["attestation"],
      "| alg =", [p["alg"] for p in opts["pubKeyCredParams"]][:3], "...")
cred = real.create(opts)
cd = json.loads(unb64u(cred["response"]["clientDataJSON"]))
print("  clientDataJSON.origin =", cd["origin"], "| type =", cd["type"])
show("", *post("/register/verify", {"user_name": USER, "credential": cred}))

print("\n[2] 진짜 출처에서 로그인")
opts = post("/login/options", {"user_name": USER})[1]
show("", *post("/login/verify", {"user_name": USER, "credential": real.get(opts)}))

print("\n[3] 피싱 출처", PHISH, "가 진짜 서버의 챌린지를 받아 와서 RP ID 'localhost'로 요청")
opts = post("/login/options", {"user_name": USER})[1]
try:
    phish.get(opts)
except PermissionError as e:
    print("  ", e)
print("   -> 서명 자체가 만들어지지 않는다")

print("\n[3b] 피싱 출처가 자기 RP ID 'shop-login.lab.example'로 요청")
opts2 = dict(opts, rpId="shop-login.lab.example")
try:
    phish.get(opts2)
except LookupError as e:
    print("  ", e)
print("   -> 인증기에 그 이름으로 저장된 패스키가 없다")

print("\n[4] (흉내) 망가진 클라이언트가 피싱 출처에서 서명을 만들어 진짜 서버로 중계")
c = auth.creds["localhost"][0]
for origin, label, rp_for_hash in [
        (PHISH, "rpIdHash=sha256('shop-login.lab.example')", "shop-login.lab.example"),
        (PHISH, "rpIdHash=sha256('localhost')", "localhost"),
        (REAL, "rpIdHash=sha256('shop-login.lab.example')", "shop-login.lab.example")]:
    opts = post("/login/options", {"user_name": USER})[1]
    cdj = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"],
                      "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode()
    ad, sig = auth.raw_sign(c, rp_for_hash, hashlib.sha256(cdj).digest())
    print(f"  origin={origin}, {label}")
    show("", *post("/login/verify", {"user_name": USER, "credential": assertion_json(c, cdj, ad, sig)}))

print("\n[5] 진짜 출처에서 받은 로그인 응답을 그대로 다시 보내기(재전송)")
opts = post("/login/options", {"user_name": USER})[1]
good = real.get(opts)
show("", *post("/login/verify", {"user_name": USER, "credential": good}))
post("/login/options", {"user_name": USER})  # 새 챌린지가 발급된 상태
show("", *post("/login/verify", {"user_name": USER, "credential": good}))

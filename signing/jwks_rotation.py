"""ES256 JWT + JWKS(kid) 키 교체를 한 번에 돌려 본다(6편).

127.0.0.1:18410 에 JWKS 엔드포인트(/.well-known/jwks.json)를 띄우고,
검증 쪽은 PyJWKClient로 그 주소에서 공개키를 받아 검증한다.

  1단계  JWKS = {k-2026-10}           옛 키로 서명한 토큰 A
  2단계  JWKS = {k-2026-10, k-2026-11} 겹치는 기간. 새 키로 서명한 토큰 B. A·B 모두 통과
  3단계  JWKS = {k-2026-11}           옛 키 퇴역. A 실패, B 통과

    ../.venv/bin/python jwks_rotation.py
"""
import base64, json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import jwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives.asymmetric import ec

PORT = 18410
ISS, AUD = "https://auth.lab.example", "orders-api"
JWKS = {"keys": []}          # 서버가 내보내는 공개키 묶음(개인키는 절대 넣지 않는다)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/.well-known/jwks.json":
            self.send_error(404); return
        body = json.dumps(JWKS).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

def new_key(kid):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(priv.public_key()))
    pub.update(kid=kid, use="sig", alg="ES256")
    return priv, pub

def issue(priv, kid, sub):
    now = int(time.time())
    return jwt.encode({"iss": ISS, "aud": AUD, "sub": sub, "iat": now, "exp": now + 600},
                      priv, algorithm="ES256", headers={"kid": kid})

def verify(token, label):
    # 매번 새 클라이언트: 캐시 없이 지금 JWKS를 본다(운영에서는 캐시 + kid 미스 시 재조회)
    client = PyJWKClient(f"http://127.0.0.1:{PORT}/.well-known/jwks.json", cache_jwk_set=False)
    try:
        key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["ES256"], audience=AUD, issuer=ISS)
        print(f"  {label}: 통과 (kid={key.key_id}, sub={claims['sub']})")
    except Exception as e:
        print(f"  {label}: 실패 {type(e).__name__}: {e}")

def publish(*pubs):
    JWKS["keys"] = list(pubs)
    return [k["kid"] for k in pubs]

srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

k1, k1pub = new_key("k-2026-10")
k2, k2pub = new_key("k-2026-11")

print("1단계 JWKS kid =", publish(k1pub))
tok_a = issue(k1, "k-2026-10", "user-1001")
print("  토큰 A 머리:", jwt.get_unverified_header(tok_a))
verify(tok_a, "토큰 A(옛 키)")

print("2단계 JWKS kid =", publish(k1pub, k2pub))
tok_b = issue(k2, "k-2026-11", "user-1002")
verify(tok_a, "토큰 A(옛 키)")
verify(tok_b, "토큰 B(새 키)")

print("3단계 JWKS kid =", publish(k2pub))
verify(tok_a, "토큰 A(옛 키)")
verify(tok_b, "토큰 B(새 키)")

print("덤: 변조와 알고리즘 바꿔치기")
h, p, s = tok_b.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=="))
claims["sub"] = "admin"
p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
verify(f"{h}.{p2}.{s}", "토큰 B의 sub를 admin으로 바꿈")
none_hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "k-2026-11"}).encode()).rstrip(b"=").decode()
verify(f"{none_hdr}.{p2}.", "alg=none 토큰")
print("공개 JWKS 한 줄(공개키만):", json.dumps(k2pub)[:120] + "...")
srv.shutdown()

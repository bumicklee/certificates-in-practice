"""작은 API 요청 서명 예(수업 3-3). 실제 표준은 RFC 9421 HTTP Message Signatures를 보라.

클라이언트가 '메서드 + 경로 + 시각 + nonce + 본문 해시'를 ECDSA P-256으로 서명하고,
서버는 공개키로 검증한 뒤 시각 허용 범위(300초)와 nonce 재사용을 본다.

    ../.venv/bin/python request_signing.py
"""
import base64, hashlib, json, secrets, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

client_key = ec.generate_private_key(ec.SECP256R1())
REGISTERED = {"client-orders": client_key.public_key()}   # 서버가 아는 것: 공개키뿐
SEEN_NONCES, SKEW = set(), 300

def canonical(method, path, ts, nonce, body):
    return "\n".join([method, path, str(ts), nonce, hashlib.sha256(body).hexdigest()]).encode()

def sign(method, path, body, ts=None, nonce=None):
    ts = ts or int(time.time()); nonce = nonce or secrets.token_hex(8)
    sig = client_key.sign(canonical(method, path, ts, nonce, body), ec.ECDSA(hashes.SHA256()))
    return {"X-Key-Id": "client-orders", "X-Timestamp": str(ts), "X-Nonce": nonce,
            "X-Signature": base64.b64encode(sig).decode()}

def server(method, path, body, h):
    pub = REGISTERED.get(h["X-Key-Id"])
    if pub is None: return "401 모르는 키"
    ts = int(h["X-Timestamp"])
    if abs(time.time() - ts) > SKEW: return "401 시각 범위 밖"
    try:
        pub.verify(base64.b64decode(h["X-Signature"]), canonical(method, path, ts, h["X-Nonce"], body),
                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "401 서명 불일치"
    if h["X-Nonce"] in SEEN_NONCES: return "401 재전송(nonce 재사용)"
    SEEN_NONCES.add(h["X-Nonce"])
    return "200 OK"

body = json.dumps({"order": "SN-0000-0001", "amount": 12000}).encode()
h = sign("POST", "/v1/refunds", body)
print("정상 요청                 ->", server("POST", "/v1/refunds", body, h))
print("같은 요청 다시 보내기     ->", server("POST", "/v1/refunds", body, h))
h2 = sign("POST", "/v1/refunds", body)
print("본문 금액을 바꿈          ->", server("POST", "/v1/refunds", body.replace(b"12000", b"99000"), h2))
h3 = sign("POST", "/v1/refunds", body)
print("경로를 바꿈               ->", server("POST", "/v1/admin/refunds", body, h3))
h4 = sign("POST", "/v1/refunds", body, ts=int(time.time()) - 3600)
print("한 시간 전 서명           ->", server("POST", "/v1/refunds", body, h4))

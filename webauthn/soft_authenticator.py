"""실습용 소프트웨어 인증기 + 브라우저 흉내.

- SoftAuthenticator: ES256(P-256) 키를 만들고 "none" 증명으로 등록 응답, 서명으로 로그인 응답을 만든다.
  자격 증명은 RP ID별로 저장한다(진짜 인증기처럼).
- Browser: 지금 페이지의 출처(origin)를 clientDataJSON에 넣고, 요청한 RP ID가
  그 출처의 호스트와 맞는지 먼저 확인한다(WebAuthn 사양의 클라이언트 쪽 검사).
  페이지 스크립트는 clientDataJSON.origin을 고칠 수 없다. 출처는 브라우저가 채운다.
실습 전용. 실제 인증기·브라우저를 대신하지 않는다.
"""
import base64, hashlib, json, os, struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    AAGUID = b"\x00" * 16  # "none" 증명이므로 0

    def __init__(self):
        self.creds = {}  # rp_id -> list of {id, key, user_handle, count}

    def make_credential(self, rp_id: str, user_handle: bytes, client_data_hash: bytes):
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(32)
        nums = key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
                            -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        flags = 0x01 | 0x04 | 0x40  # UP, UV, AT
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
                     + self.AAGUID + struct.pack(">H", len(cred_id)) + cred_id + cose)
        self.creds.setdefault(rp_id, []).append(
            {"id": cred_id, "key": key, "user_handle": user_handle, "count": 0})
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return cred_id, att_obj

    def get_assertion(self, rp_id: str, client_data_hash: bytes, allow_ids=None):
        cands = [c for c in self.creds.get(rp_id, [])
                 if not allow_ids or c["id"] in allow_ids]
        if not cands:
            raise LookupError(f"인증기: RP ID '{rp_id}'용 자격 증명이 없음")
        c = cands[0]
        c["count"] += 1
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", c["count"])
        sig = c["key"].sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
        return c, auth_data, sig

    # 실습 4번(중계 공격 흉내)에서만 쓴다: 이미 받은 자격 증명으로, 지정한 RP ID 해시를 넣어 서명
    def raw_sign(self, cred, rp_id_for_hash: str, client_data_hash: bytes):
        cred["count"] += 1
        auth_data = (hashlib.sha256(rp_id_for_hash.encode()).digest() + bytes([0x05])
                     + struct.pack(">I", cred["count"]))
        return auth_data, cred["key"].sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))


def host_of(origin: str) -> str:
    return origin.split("://", 1)[1].split(":")[0].split("/")[0]


def rp_id_allowed(origin_host: str, rp_id: str) -> bool:
    # 사양: RP ID는 출처의 호스트와 같거나 그 등록 가능한 상위 도메인이어야 한다(공개 접미사 제외).
    return origin_host == rp_id or origin_host.endswith("." + rp_id)


class Browser:
    def __init__(self, authenticator: SoftAuthenticator, origin: str):
        self.a = authenticator
        self.origin = origin  # 지금 열린 탭의 주소창 출처. 페이지가 바꿀 수 없다.

    def _client_data(self, typ: str, challenge_b64u: str) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64u,
                           "origin": self.origin, "crossOrigin": False},
                          separators=(",", ":")).encode()

    def create(self, opts: dict) -> dict:
        rp_id = opts["rp"].get("id") or host_of(self.origin)
        if not rp_id_allowed(host_of(self.origin), rp_id):
            raise PermissionError(f"브라우저: 출처 {self.origin} 에서 RP ID '{rp_id}' 사용 불가 (SecurityError)")
        cd = self._client_data("webauthn.create", opts["challenge"])
        cred_id, att = self.a.make_credential(rp_id, unb64u(opts["user"]["id"]), hashlib.sha256(cd).digest())
        return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att),
                             "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def get(self, opts: dict) -> dict:
        rp_id = opts.get("rpId") or host_of(self.origin)
        if not rp_id_allowed(host_of(self.origin), rp_id):
            raise PermissionError(f"브라우저: 출처 {self.origin} 에서 RP ID '{rp_id}' 사용 불가 (SecurityError)")
        cd = self._client_data("webauthn.get", opts["challenge"])
        allow = [unb64u(c["id"]) for c in opts.get("allowCredentials", [])]
        c, ad, sig = self.a.get_assertion(rp_id, hashlib.sha256(cd).digest(), allow)
        return assertion_json(c, cd, ad, sig)


def assertion_json(c, cd, ad, sig):
    return {"id": b64u(c["id"]), "rawId": b64u(c["id"]), "type": "public-key",
            "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad),
                         "signature": b64u(sig), "userHandle": b64u(c["user_handle"])},
            "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

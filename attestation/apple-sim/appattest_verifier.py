"""29편: App Attest 서버 검증 (Apple 문서 'Validating apps that connect to your server'의 단계 순서).

  verify_attestation()  증명 객체(CBOR) → 공개키·receipt를 돌려준다. 실패하면 Reject
  verify_assertion()    이후 요청마다 오는 assertion(CBOR) 검증. 카운터가 늘어야 한다

학습용이다. 실기기 객체와 바이트 단위로 맞는지는 Apple 예제 객체(apple/sample_attestation.b64)로만 확인했다.
"""
import hashlib, hmac, io, struct
import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID = {"development": b"appattestdevelop", "production": b"appattest" + b"\x00" * 7}


class Reject(Exception):
    pass


def parse_auth_data(ad: bytes):
    """WebAuthn authenticator data 모양. 증명용은 길고, assertion용은 앞 37바이트(+확장)만 있다."""
    out = {"rpIdHash": ad[:32], "flags": ad[32], "counter": struct.unpack(">I", ad[33:37])[0]}
    rest = ad[37:]
    if out["flags"] & 0x40:                          # AT: 증명된 자격 데이터가 붙어 있다
        out["aaguid"] = rest[:16]
        n = struct.unpack(">H", rest[16:18])[0]
        out["credentialId"] = rest[18:18 + n]
        buf = io.BytesIO(rest[18 + n:])
        out["coseKey"] = cbor2.CBORDecoder(buf).decode()
        out["coseKeyLen"] = buf.tell()
        rest = buf.read()
    if rest:                                         # 확장 CBOR 맵 (Apple 예제 객체는 ED 플래그 없이도 붙어 있다)
        out["extensions"] = cbor2.loads(rest)
    return out


def _nonce_from_cert(cert):
    # 확장 값 = DER SEQUENCE 안의 단일 OCTET STRING (Apple 예제: 30 24 A1 22 04 20 <32바이트>)
    der = cert.extensions.get_extension_for_oid(NONCE_OID).value.value
    i = der.index(b"\x04\x20")
    return der[i + 2:i + 34]


def verify_attestation(att_obj: bytes, key_id: bytes, client_data_hash: bytes, app_id: str,
                       trusted_root: x509.Certificate, env: str, now, policy=None, log=None):
    policy = policy or {}
    say = log or (lambda *_: None)
    o = cbor2.loads(att_obj)
    if o.get("fmt") != "apple-appattest":
        raise Reject(f"fmt is {o.get('fmt')!r}")
    certs = [x509.load_der_x509_certificate(c) for c in o["attStmt"]["x5c"]]
    cred, chain = certs[0], certs + [trusted_root]
    # 1) x5c = [credCert, 중간]; 신뢰 루트(내가 가진 Apple App Attestation Root CA)까지 서명·기간 확인
    for child, parent in zip(chain, chain[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature):
            raise Reject(f"step1 chain: {child.subject.rfc4514_string()} not issued by {parent.subject.rfc4514_string()}")
        if not (child.not_valid_before_utc <= now <= child.not_valid_after_utc):
            raise Reject(f"step1 chain: {child.subject.rfc4514_string()} not valid at {now:%Y-%m-%d}")
    say(1, "x5c chains to trusted root", trusted_root.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
    # 2~4) nonce = SHA256(authData || clientDataHash) 가 credCert 확장 1.2.840.113635.100.8.2 값과 같아야 한다
    auth = o["authData"]
    nonce = hashlib.sha256(auth + client_data_hash).digest()
    if not hmac.compare_digest(nonce, _nonce_from_cert(cred)):
        raise Reject("step4 nonce mismatch (wrong challenge or replay)")
    say(4, "nonce == credCert ext 1.2.840.113635.100.8.2", nonce.hex()[:16] + "…")
    # 5) SHA256(공개키, X9.62 비압축 점) == keyId
    pub = cred.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if hashlib.sha256(pub).digest() != key_id:
        raise Reject("step5 public key hash != keyId")
    say(5, "SHA256(credCert pubkey) == keyId", key_id.hex()[:16] + "…")
    ad = parse_auth_data(auth)
    # 6) RP ID = SHA256("TeamID.BundleID")
    if ad["rpIdHash"] != hashlib.sha256(app_id.encode()).digest():
        raise Reject(f"step6 rpIdHash != SHA256({app_id!r})")
    say(6, "rpIdHash == SHA256(App ID)", app_id)
    # 7) 카운터 0
    if ad["counter"] != 0:
        raise Reject(f"step7 counter is {ad['counter']}, expected 0")
    say(7, "counter == 0", "0")
    # 8) aaguid: 운영이면 'appattest'+0x00*7, 개발이면 'appattestdevelop'
    if ad["aaguid"] != AAGUID[env]:
        raise Reject(f"step8 aaguid {ad['aaguid']!r} not allowed in {env}")
    say(8, f"aaguid ok for {env}", repr(ad["aaguid"]))
    # 9) credentialId == keyId
    if ad["credentialId"] != key_id:
        raise Reject("step9 credentialId != keyId")
    say(9, "credentialId == keyId", f"{len(ad['credentialId'])} bytes")
    # 10~11) 확장: apple_validation_category_01, apple_bundle_version_01 (정책 값은 서비스가 정한다)
    ext = ad.get("extensions", {})
    for n, k in ((10, "apple_validation_category_01"), (11, "apple_bundle_version_01")):
        if k in policy and ext.get(k) != policy[k]:
            raise Reject(f"step{n} {k}={ext.get(k)!r}, expected {policy[k]!r}")
        if k in policy:
            say(n, f"{k} == policy", repr(ext.get(k)))
    return {"publicKey": cred.public_key(), "receipt": o["attStmt"]["receipt"], "authData": ad}


def verify_assertion(assertion: bytes, client_data: bytes, expected_challenge: bytes, challenge_in_client_data: bytes,
                     app_id: str, stored: dict):
    """stored = {"publicKey":…, "counter": 직전 카운터}. 통과하면 stored["counter"]를 갱신한다."""
    a = cbor2.loads(assertion)
    auth, sig = a["authenticatorData"], a["signature"]
    nonce = hashlib.sha256(auth + hashlib.sha256(client_data).digest()).digest()      # 1~2
    try:                                                                                 # 3
        stored["publicKey"].verify(sig, nonce, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Reject("assert3 bad signature")
    ad = parse_auth_data(auth)
    if ad["rpIdHash"] != hashlib.sha256(app_id.encode()).digest():                        # 4
        raise Reject("assert4 rpIdHash mismatch")
    if ad["counter"] <= stored["counter"]:                                               # 5
        raise Reject(f"assert5 counter {ad['counter']} <= stored {stored['counter']} (replay)")
    if not hmac.compare_digest(challenge_in_client_data, expected_challenge):            # 6
        raise Reject("assert6 challenge mismatch")
    stored["counter"] = ad["counter"]
    return ad["counter"]

"""서버 쪽 키 증명 검증 골격 (Android Key Attestation 모양). 수업 9-2.

진짜 Android와 같은 점
  - 기기가 보낸 인증서 사슬 [리프(증명 대상 키), 중간…, 루트]를 서버가 검증한다
  - 루트는 서버가 가진 신뢰 목록과 '공개키'로 비교한다. 목록에는 옛 루트와 새 루트가 함께 있어야 한다
  - 리프의 증명 확장에서 챌린지·보안 수준·부팅 상태를 읽어 정책으로 판단한다
  - 사슬에 있는 인증서 일련번호를 폐기 목록(status)과 대조한다
진짜와 다른 점(실습용 단순화)
  - 확장 OID: 진짜는 1.3.6.1.4.1.11129.2.1.17 (KeyDescription, ASN.1 SEQUENCE).
    여기서는 문서용 PEN 32473 아래 1.3.6.1.4.1.32473.1.17 에 JSON을 넣었다. 실서비스에서는 ASN.1을 파싱한다
  - 루트·중간은 모두 가짜. 진짜 루트 목록: https://android.googleapis.com/attestation/root
"""
import hmac, json
from cryptography import x509
from cryptography.hazmat.primitives import serialization

LAB_ATTEST_OID = x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.17")
REAL_ANDROID_OID = "1.3.6.1.4.1.11129.2.1.17"


class Reject(Exception):
    pass


def _spki(c):
    return c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_attestation(chain_pem: str, expected_challenge: bytes, trusted_roots: list, revoked: dict, now):
    chain = x509.load_pem_x509_certificates(chain_pem.encode())
    leaf, root = chain[0], chain[-1]
    # 1) 루트: 신뢰 목록의 공개키와 같아야 한다(이름만 같은 가짜 루트를 막는다)
    match = [r for r in trusted_roots if _spki(r) == _spki(root)]
    if not match:
        raise Reject(f"untrusted root: {root.subject.rfc4514_string()}")
    # 2) 사슬: 각 인증서가 바로 위 인증서로 서명됐는지, 위쪽은 CA인지, CA 유효 기간
    for child, parent in zip(chain, chain[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except Exception as e:
            raise Reject(f"bad signature: {child.subject.rfc4514_string()} ← {parent.subject.rfc4514_string()} ({e})")
        if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise Reject("issuer is not a CA")
        if not (parent.not_valid_before_utc <= now <= parent.not_valid_after_utc):
            raise Reject(f"CA not valid now: {parent.subject.rfc4514_string()}")
    # 3) 폐기 목록 (진짜 형식: {"entries": {"<일련번호 16진수>": {"status": "REVOKED", ...}}})
    for c in chain:
        e = revoked.get("entries", {}).get(format(c.serial_number, "x"))
        if e:
            raise Reject(f"revoked: {c.subject.rfc4514_string()} ({e.get('reason')})")
    # 4) 증명 확장
    try:
        desc = json.loads(leaf.extensions.get_extension_for_oid(LAB_ATTEST_OID).value.value)
    except x509.ExtensionNotFound:
        raise Reject("no attestation extension")
    if not hmac.compare_digest(bytes.fromhex(desc["attestationChallenge"]), expected_challenge):
        raise Reject("challenge mismatch (replay or wrong session)")
    # 5) 정책: 여기서부터는 서비스가 정한다
    if desc["attestationSecurityLevel"] not in ("TrustedEnvironment", "StrongBox"):
        raise Reject(f"key not in hardware: {desc['attestationSecurityLevel']}")
    rot = desc["rootOfTrust"]
    if rot["verifiedBootState"] != "Verified" or not rot["deviceLocked"]:
        raise Reject(f"boot state {rot['verifiedBootState']}, locked={rot['deviceLocked']}")
    return {"root": match[0].subject.rfc4514_string(), "securityLevel": desc["attestationSecurityLevel"],
            "attestedKey": leaf.public_key().public_numbers().curve.name if hasattr(leaf.public_key(), "curve") else "rsa"}

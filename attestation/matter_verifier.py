"""Matter식 기기 증명 검증 골격 (커미셔너 쪽). 수업 9-2.

사슬: PAA(제조사 루트, DCL에 등록) → PAI(제품 중간) → DAC(기기마다 하나, 공장에서 주입)
VID/PID는 인증서 Subject의 Matter OID에 들어 있다: 1.3.6.1.4.1.37244.2.1(VID), .2.2(PID)
단순화: Certification Declaration(CD)의 CSA 서명 검증과 TLV 인코딩은 생략하고 JSON으로 흉내 낸다.
"""
import hmac, json
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

VID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")
PID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")


class Reject(Exception):
    pass


def _attr(c, oid):
    a = c.subject.get_attributes_for_oid(oid)
    return a[0].value if a else None


def _skid(c): return c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
def _akid(c): return c.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier.hex()


def verify_device(dac_pem, pai_pem, elements: bytes, signature: bytes, nonce: bytes, challenge: bytes, dcl: dict, now):
    dac, pai = x509.load_pem_x509_certificate(dac_pem.encode()), x509.load_pem_x509_certificate(pai_pem.encode())
    # 1) PAA는 기기가 아니라 DCL에서 찾는다
    paa_entry = next((p for p in dcl["paa"] if p["subjectKeyId"] == _akid(pai)), None)
    if not paa_entry:
        raise Reject("PAA not in DCL (counterfeit or uncertified vendor)")
    paa = x509.load_pem_x509_certificate(paa_entry["pem"].encode())
    # 2) 사슬 서명과 유효 기간
    for child, parent in ((dac, pai), (pai, paa)):
        try:
            child.verify_directly_issued_by(parent)
        except Exception:
            raise Reject(f"bad chain signature: {child.subject.rfc4514_string()}")
        if not (child.not_valid_before_utc <= now <= child.not_valid_after_utc):
            raise Reject(f"not valid now: {child.subject.rfc4514_string()}")
    # 3) 폐기: PAI·PAA
    if format(pai.serial_number, "x") in dcl.get("revoked_pai_serials", []):
        raise Reject("PAI revoked in DCL")
    # 4) VID/PID 일치
    vid = _attr(dac, VID_OID)
    if vid != _attr(pai, VID_OID) or (_attr(paa, VID_OID) not in (None, vid)):
        raise Reject(f"VID mismatch: DAC {vid} / PAI {_attr(pai, VID_OID)} / PAA {_attr(paa, VID_OID)}")
    pid = _attr(dac, PID_OID)
    if _attr(pai, PID_OID) not in (None, pid):
        raise Reject(f"PID mismatch: DAC {pid} / PAI {_attr(pai, PID_OID)}")
    # 5) 증명 요소: 커미셔너가 보낸 32바이트 nonce가 그대로 들어 있어야 한다
    el = json.loads(elements)
    if not hmac.compare_digest(bytes.fromhex(el["attestation_nonce"]), nonce):
        raise Reject("attestation nonce mismatch (replay)")
    cd = el["certification_declaration"]
    if cd["vendor_id"] != vid or pid not in cd["product_id_array"]:
        raise Reject("Certification Declaration does not cover this VID/PID")
    # 6) DAC 개인키로 한 서명: (증명 요소 || 세션 챌린지). 인증서만 복사한 복제품은 여기서 걸린다
    try:
        dac.public_key().verify(signature, elements + challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Reject("attestation signature invalid (DAC private key not present)")
    return {"vid": vid, "pid": pid, "paa": paa.subject.rfc4514_string()}

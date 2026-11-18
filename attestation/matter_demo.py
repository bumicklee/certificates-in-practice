#!/usr/bin/env python3
"""수업 9-2 Matter식 PAA → PAI → DAC 검증. DCL은 로컬 JSON 파일(out/dcl.json).
   ../.venv/bin/python matter_demo.py
"""
import json, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fakepki import NOW, ca_pair, cert, key, name, pem
from matter_verifier import PID_OID, VID_OID, Reject, verify_device

HERE = os.path.dirname(os.path.abspath(__file__))
V = lambda vid: x509.NameAttribute(VID_OID, vid)
P = lambda pid: x509.NameAttribute(PID_OID, pid)

# 제조사(시험용 VID 0xFFF1)의 PAA와 제품 PAI. 위조품 업체는 자기 PAA를 DCL에 올리지 못했다
PAA = ca_pair("FAKE Matter PAA FFF1", extra=[V("FFF1")])
PAI = ca_pair("FAKE Matter PAI FFF1-8000", issuer=PAA, extra=[V("FFF1"), P("8000")], path_len=0)
BAD_PAA = ca_pair("FAKE Counterfeit PAA", extra=[V("FFF1")])
BAD_PAI = ca_pair("FAKE Counterfeit PAI", issuer=BAD_PAA, extra=[V("FFF1"), P("8000")], path_len=0)

os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
DCL_PATH = os.path.join(HERE, "out/dcl.json")
skid = lambda c: c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
json.dump({"paa": [{"vid": "FFF1", "subjectKeyId": skid(PAA[0]), "pem": pem(PAA[0])}], "revoked_pai_serials": []},
          open(DCL_PATH, "w"), indent=2)


class Device:
    def __init__(self, pai, vid="FFF1", pid="8000"):
        self.pai = pai
        self.key = key("p256")                     # DAC 개인키: 공장에서 보안 영역에 넣는다
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(pai[1].public_key())
        self.dac = cert(name(f"FAKE Matter DAC {vid}-{pid}", [V(vid), P(pid)]), self.key.public_key(),
                        pai[0].subject, pai[1], ca=False, days=3650, exts=[aki])

    def attest(self, nonce, challenge):
        elements = json.dumps({"certification_declaration": {"vendor_id": "FFF1", "product_id_array": ["8000"]},
                               "attestation_nonce": nonce.hex()}).encode()
        return pem(self.dac), pem(self.pai[0]), elements, self.key.sign(elements + challenge, ec.ECDSA(hashes.SHA256()))


def add_aki(pai_pair, issuer):
    """PAI에 AKID를 넣어 다시 만든다(DCL에서 PAA를 찾는 열쇠)."""
    c, k = pai_pair
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[1].public_key())
    return cert(c.subject, k.public_key(), issuer[0].subject, issuer[1], ca=True, path_len=0, exts=[aki]), k


PAI, BAD_PAI = add_aki(PAI, PAA), add_aki(BAD_PAI, BAD_PAA)


def run(label, dev, tamper=None):
    dcl = json.load(open(DCL_PATH))
    nonce, challenge = os.urandom(32), os.urandom(16)     # nonce: 커미셔너가 만든 32바이트
    dac, pai, el, sig = dev.attest(nonce, challenge)
    if tamper == "old_nonce":
        dac, pai, el, sig = dev.attest(os.urandom(32), challenge)
    if tamper == "clone":
        _, _, el, sig = Device(PAI).attest(nonce, challenge)    # 인증서는 진품에서 복사, 키는 없음 → 자기 키로 서명
    try:
        r = verify_device(dac, pai, el, sig, nonce, challenge, dcl, NOW)
        print(f"PASS  {label:<44} VID={r['vid']} PID={r['pid']} PAA={r['paa']!r}")
    except Reject as e:
        print(f"FAIL  {label:<44} {e}")


print(f"DCL: {os.path.relpath(DCL_PATH, HERE)} (PAA {len(json.load(open(DCL_PATH))['paa'])}개)")
good = Device(PAI)
run("genuine device", good)
run("counterfeit (PAA not in DCL)", Device(BAD_PAI))
run("DAC VID FFF2 under PAI FFF1", Device(PAI, vid="FFF2"))
run("DAC PID 8001 under PAI PID 8000", Device(PAI, pid="8001"))
run("replayed answer (old nonce)", good, tamper="old_nonce")
run("cloned DAC cert without its private key", good, tamper="clone")
d = json.load(open(DCL_PATH)); d["revoked_pai_serials"].append(format(PAI[0].serial_number, "x"))
json.dump(d, open(DCL_PATH, "w"), indent=2)
run("genuine device after PAI revoked in DCL", good)

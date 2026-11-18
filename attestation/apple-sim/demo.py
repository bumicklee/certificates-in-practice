#!/usr/bin/env python3
"""수업 9-4 App Attest 서버 검증 실습.
  ../../.venv/bin/python -I demo.py

A. Apple 문서의 예제 증명 객체(진짜 Apple 사슬)를 진짜 Apple App Attestation Root CA로 검증
B. 가짜 루트·가짜 기기로 성공 1건과 실패 사례
C. assertion: 카운터 증가, 재전송, 변조
"""
import base64, datetime as dt, hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography import x509
from appattest_verifier import Reject, parse_auth_data, verify_assertion, verify_attestation
from fake_device import NOW, FakeAttestationCA, FakeDevice
import cbor2

HERE = os.path.dirname(os.path.abspath(__file__))


def show(n, name, why):
    print(f"    step{n:<2} PASS  {name:<44} {why}")


def attempt(label, **kw):
    print(f"  [{label}]")
    try:
        r = verify_attestation(log=show, **kw)
        print("    => ACCEPT  (store publicKey + receipt per keyId, counter=0)")
        return r
    except Reject as e:
        print(f"    => REJECT  {e}")


# ---------------------------------------------------------------- A
print("== A. Apple sample attestation object (attestation-object-validation-guide)")
apple_root = x509.load_pem_x509_certificate(open(f"{HERE}/apple/Apple_App_Attestation_Root_CA.pem", "rb").read())
inp = json.load(open(f"{HERE}/apple/sample_inputs.json"))
att = base64.b64decode(open(f"{HERE}/apple/sample_attestation.b64").read())
o = cbor2.loads(att)
ad = parse_auth_data(o["authData"])
cred = x509.load_der_x509_certificate(o["attStmt"]["x5c"][0])
inter = x509.load_der_x509_certificate(o["attStmt"]["x5c"][1])
print(f"  top-level keys: {list(o)}  fmt={o['fmt']!r}")
print(f"  attStmt.x5c: {len(o['attStmt']['x5c'])} certs, receipt {len(o['attStmt']['receipt'])} bytes (PKCS#7)")
print(f"    x5c[0] {cred.subject.rfc4514_string()[:70]}…  {cred.not_valid_before_utc:%Y-%m-%d %H:%M}~{cred.not_valid_after_utc:%Y-%m-%d %H:%M}")
print(f"    x5c[1] {inter.subject.rfc4514_string()}  ~{inter.not_valid_after_utc:%Y-%m-%d}")
import warnings
from cryptography.hazmat.primitives.serialization import pkcs7
with warnings.catch_warnings():
    warnings.simplefilter("ignore")      # receipt는 BER(길이 미정) 인코딩이라 경고가 난다
    for c in pkcs7.load_der_pkcs7_certificates(o["attStmt"]["receipt"]):
        print(f"    receipt cert: {c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}")
print(f"  authData {len(o['authData'])} bytes: rpIdHash={ad['rpIdHash'].hex()[:16]}… flags=0x{ad['flags']:02x} counter={ad['counter']}")
print(f"    aaguid={ad['aaguid']!r} credentialId={ad['credentialId'].hex()[:16]}… coseKey={ad['coseKeyLen']} bytes")
print(f"    extensions={ {k: v for k, v in ad.get('extensions', {}).items()} }")
app_id = f"{inp['appIDPrefix']}.{inp['bundleID']}"
key_id = base64.b64decode(inp["keyId"])
ch = inp["serverChallenge"].encode()
at_capture = cred.not_valid_before_utc + dt.timedelta(hours=1)
common = dict(att_obj=att, key_id=key_id, app_id=app_id, trusted_root=apple_root, env="production")
attempt(f"clientDataHash = challenge bytes as in Apple's sample, at {at_capture:%Y-%m-%d}",
        client_data_hash=ch, now=at_capture, **common)
attempt("clientDataHash = SHA256(challenge) (wording of step 2)",
        client_data_hash=hashlib.sha256(ch).digest(), now=at_capture, **common)
attempt(f"same object checked now ({NOW:%Y-%m-%d})", client_data_hash=ch, now=NOW, **common)

# ---------------------------------------------------------------- B
print("\n== B. simulator: FAKE root (lab only, not Apple)")
ca = FakeAttestationCA()
APP = "FAKETEAM01.com.example.shop"
POLICY = {"apple_bundle_version_01": "1.0"}
print(f"  fake root: {ca.root.subject.rfc4514_string()}  (P-384)")


def server_challenge(): return os.urandom(32)


dev = FakeDevice(ca, APP, "production")
ch = server_challenge()
dev.generate_key()
obj = dev.attest_key(hashlib.sha256(ch).digest())
base = dict(key_id=dev.key_id, app_id=APP, trusted_root=ca.root, env="production", now=NOW, policy=POLICY)
stored = attempt("valid (production)", att_obj=obj, client_data_hash=hashlib.sha256(ch).digest(), **base)

d2 = FakeDevice(ca, "FAKETEAM01.com.example.shop-clone"); d2.generate_key()
c2 = server_challenge()
attempt("wrong App ID (repackaged bundle id)", att_obj=d2.attest_key(hashlib.sha256(c2).digest()),
        client_data_hash=hashlib.sha256(c2).digest(), **dict(base, key_id=d2.key_id))

attempt("wrong nonce (old attestation replayed in new session)", att_obj=obj,
        client_data_hash=hashlib.sha256(server_challenge()).digest(), **base)

d3 = FakeDevice(ca, APP, "development"); d3.generate_key()
c3 = server_challenge()
attempt("development aaguid under production policy", att_obj=d3.attest_key(hashlib.sha256(c3).digest()),
        client_data_hash=hashlib.sha256(c3).digest(), **dict(base, key_id=d3.key_id))

rogue = FakeAttestationCA(root_cn="FAKE App Attestation Root CA (lab, not Apple)")   # 이름은 같고 키가 다른 루트
d4 = FakeDevice(rogue, APP); d4.generate_key()
c4 = server_challenge()
attempt("unknown root (same name, different key)", att_obj=d4.attest_key(hashlib.sha256(c4).digest()),
        client_data_hash=hashlib.sha256(c4).digest(), **dict(base, key_id=d4.key_id))

attempt("Apple sample object checked against the FAKE root", att_obj=att, client_data_hash=inp["serverChallenge"].encode(),
        **dict(base, key_id=key_id, app_id=app_id, trusted_root=ca.root, now=at_capture, policy={}))

# ---------------------------------------------------------------- C
print("\n== C. assertions (stored public key, counter)")
st = {"publicKey": stored["publicKey"], "counter": 0}


def req(label, assertion, client_data, expected):
    try:
        cd = json.loads(client_data)
        n = verify_assertion(assertion, client_data, expected, bytes.fromhex(cd["challenge"]), APP, st)
        print(f"  PASS  {label:<48} counter={n}")
    except Reject as e:
        print(f"  FAIL  {label:<48} {e}")


for i in (1, 2):
    c = server_challenge()
    cd = json.dumps({"action": "getPremium", "levelId": "SN-0000-0001", "challenge": c.hex()}).encode()
    a = dev.generate_assertion(cd)
    req(f"assertion #{i}", a, cd, c)
req("same assertion #2 sent again", a, cd, c)
c = server_challenge()
cd = json.dumps({"action": "getPremium", "levelId": "SN-0000-0001", "challenge": c.hex()}).encode()
a = dev.generate_assertion(cd)
req("clientData changed after signing", a, cd.replace(b"SN-0000-0001", b"SN-0000-9999"), c)
c_old = c
c = server_challenge()
cd = json.dumps({"action": "getPremium", "levelId": "SN-0000-0001", "challenge": c_old.hex()}).encode()
req("signed with an old challenge", dev.generate_assertion(cd), cd, c)

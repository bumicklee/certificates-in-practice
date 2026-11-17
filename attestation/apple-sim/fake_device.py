"""29편: App Attest 모양을 흉내 내는 '가짜 기기'. Apple과 무관한 실습용이다.

- 루트는 가짜: 'FAKE App Attestation Root CA (lab, not Apple)'. 진짜 Apple 루트 키는 Apple만 가진다
- 실제 기기에서는 키가 Secure Enclave에서 만들어지고, 인증서는 Apple 서버가 발급한다.
  여기서는 한 프로세스 안에서 전부 흉내 낸다
"""
import datetime as dt, hashlib, json, struct
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)
NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID = {"development": b"appattestdevelop", "production": b"appattest" + b"\x00" * 7}


def _name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAKE Lab")])


def _cert(subj, pub, iss_name, iss_key, ca, days, exts=()):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss_name).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(hours=1))
         .not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(iss_key, hashes.SHA384() if iss_key.curve.key_size == 384 else hashes.SHA256())


class FakeAttestationCA:
    """가짜 '증명 서버' 쪽: 루트(P-384) → 중간(P-384). 이름은 Apple 구조를 따라 했지만 FAKE 표시."""
    def __init__(self, root_cn="FAKE App Attestation Root CA (lab, not Apple)"):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert(_name(root_cn), self.root_key.public_key(), _name(root_cn), self.root_key, True, 3650)
        self.int_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = _cert(_name("FAKE App Attestation CA 1"), self.int_key.public_key(), self.root.subject,
                           self.root_key, True, 3650)

    def issue_cred_cert(self, pub, key_id, nonce):
        ext = x509.UnrecognizedExtension(NONCE_OID, bytes.fromhex("3024a1220420") + nonce)  # SEQUENCE{[1]{OCTET STRING}}
        return _cert(_name(key_id.hex()), pub, self.inter.subject, self.int_key, False, 3, [ext])   # Apple 예제도 3일짜리


class FakeDevice:
    """앱 한 개(App ID)가 깔린 기기. Secure Enclave 대신 메모리 키."""
    def __init__(self, ca, app_id, env="production", bundle_version="1.0"):
        self.ca, self.app_id, self.env, self.bundle_version = ca, app_id, env, bundle_version
        self.counter = 0

    def generate_key(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        pub = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.key_id = hashlib.sha256(pub).digest()
        return self.key_id

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def attest_key(self, client_data_hash):
        rp = hashlib.sha256(self.app_id.encode()).digest()
        ext = cbor2.dumps({"apple_bundle_version_01": self.bundle_version,
                           "apple_validation_category_01": struct.pack("<I", 1)})
        auth = (rp + bytes([0x40]) + struct.pack(">I", 0) + AAGUID[self.env]
                + struct.pack(">H", 32) + self.key_id + self._cose() + ext)
        nonce = hashlib.sha256(auth + client_data_hash).digest()
        cred = self.ca.issue_cred_cert(self.key.public_key(), self.key_id, nonce)
        der = lambda c: c.public_bytes(serialization.Encoding.DER)
        return cbor2.dumps({"fmt": "apple-appattest",
                            "attStmt": {"x5c": [der(cred), der(self.ca.inter)], "receipt": b"FAKE-RECEIPT-NOT-FROM-APPLE"},
                            "authData": auth})

    def generate_assertion(self, client_data: bytes):
        self.counter += 1
        auth = hashlib.sha256(self.app_id.encode()).digest() + bytes([0x00]) + struct.pack(">I", self.counter)
        nonce = hashlib.sha256(auth + hashlib.sha256(client_data).digest()).digest()
        return cbor2.dumps({"signature": self.key.sign(nonce, ec.ECDSA(hashes.SHA256())), "authenticatorData": auth})

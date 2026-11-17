"""인증서·공개키에서 Android Network Security Config용 SPKI SHA-256 핀을 계산한다.

    ../.venv/bin/python compute_pins.py ../private-ca/out/root.crt ../private-ca/out/inter.crt ../private-ca/out/leaf.crt out/backup-inter.pub

핀 = base64( SHA-256( SubjectPublicKeyInfo DER ) ). 인증서가 아니라 "공개키"를 고정한다.
같은 키로 인증서를 다시 받으면 핀은 그대로다.
"""
import base64
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def spki_pin_from_public_key(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()

def pin_of(path):
    data = Path(path).read_bytes()
    if b"CERTIFICATE" in data:
        cert = x509.load_pem_x509_certificate(data)
        return cert.subject.rfc4514_string(), spki_pin_from_public_key(cert.public_key())
    pub = serialization.load_pem_public_key(data)
    return "(공개키 파일: 아직 인증서 없음)", spki_pin_from_public_key(pub)

if __name__ == "__main__":
    for p in sys.argv[1:]:
        subject, pin = pin_of(p)
        print(f"{p}\n  {subject}\n  sha256/{pin}")

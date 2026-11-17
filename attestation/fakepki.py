"""27편 공용: 가짜 CA·인증서를 메모리에서 만드는 작은 도우미. 실제 제조사·Google 키와 무관하다."""
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def name(cn, extra=()):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), *extra])


def key(kind="p256"):
    return {"p256": lambda: ec.generate_private_key(ec.SECP256R1()),
            "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
            "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)}[kind]()


def cert(subject, pub, issuer_name, issuer_key, ca, days=3650, exts=(), path_len=None, not_before=None):
    h = hashes.SHA384() if isinstance(issuer_key, ec.EllipticCurvePrivateKey) and issuer_key.curve.key_size == 384 else hashes.SHA256()
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(not_before or NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len if ca else None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(issuer_key, h)


def ca_pair(cn, kind="p256", issuer=None, extra=(), path_len=1):
    """(cert, key). issuer=None이면 자체 서명 루트."""
    k = key(kind)
    if issuer is None:
        return cert(name(cn, extra), k.public_key(), name(cn, extra), k, True, path_len=path_len), k
    ic, ik = issuer
    return cert(name(cn, extra), k.public_key(), ic.subject, ik, True, path_len=path_len), k


def pem(c): return c.public_bytes(serialization.Encoding.PEM).decode()

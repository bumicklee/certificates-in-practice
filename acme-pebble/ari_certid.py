"""ARI(RFC 9773) certID 만들기: base64url(AKI keyIdentifier) + "." + base64url(serial DER 정수 바이트)"""
import base64, sys
from cryptography import x509
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
cert = x509.load_pem_x509_certificate(open(sys.argv[1], "rb").read())
aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
n = cert.serial_number
sb = n.to_bytes((n.bit_length() + 8) // 8, "big")  # DER INTEGER: 맨 앞 비트가 1이면 0x00을 붙인다
print(f"{b64u(aki)}.{b64u(sb)}")

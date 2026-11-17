"""깨뜨린 사슬을 Python 두 가지 검증기로 돌린다.

1) cryptography.x509.verification (rust 로 만든 웹 PKI 검증기, CA/B 포럼 규칙에 가깝다)
2) ssl 모듈의 실제 TLS 핸드셰이크 (OpenSSL). 소켓 없이 메모리 안에서 서버·클라이언트를 맞붙인다.

    ../.venv/bin/python verify.py
"""
import datetime as dt
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

OUT = Path(__file__).resolve().parent / "out"
BASE = OUT / "base"

def load(p):
    return x509.load_pem_x509_certificates(Path(p).read_bytes())

# (이름, 서버가 보내는 사슬 파일, 서버 키, 접속 이름, 믿는 루트)
CASES = [
    ("0 정상", BASE / "chain.pem", BASE / "leaf.key", "shop.lab.example", BASE / "root.crt"),
    ("1 만료된 리프", OUT / "1-expired/chain.pem", OUT / "1-expired/leaf.key", "shop.lab.example", BASE / "root.crt"),
    ("2 잘못된 발급자", OUT / "2-wrong-issuer/chain.pem", OUT / "2-wrong-issuer/leaf.key", "shop.lab.example", BASE / "root.crt"),
    ("3 SAN 불일치", OUT / "3-san-mismatch/chain.pem", OUT / "3-san-mismatch/leaf.key", "shop.lab.example", BASE / "root.crt"),
    ("4 중간 누락", OUT / "4-missing-inter/chain.pem", OUT / "4-missing-inter/leaf.key", "shop.lab.example", BASE / "root.crt"),
    ("5 CA:TRUE 리프가 서명한 evil", OUT / "5-leaf-ca-true/chain.pem", OUT / "5-leaf-ca-true/evil.key", "evil.lab.example", BASE / "root.crt"),
    ("5b 허술한 CA", OUT / "5b-careless/chain.pem", OUT / "5b-careless/evil.key", "evil.lab.example", OUT / "5b-careless/root.crt"),
]

def by_cryptography(chain, host, root):
    certs = load(chain)
    verifier = (PolicyBuilder()
                .store(Store(load(root)))
                .time(dt.datetime.now(dt.timezone.utc))
                .build_server_verifier(DNSName(host)))
    try:
        verifier.verify(certs[0], certs[1:])
        return "통과"
    except VerificationError as e:
        return f"실패: {e}"

def by_ssl(chain, key, host, root):
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.load_cert_chain(chain, key)
    cli = ssl.create_default_context(cafile=str(root))   # 기본: 이름 확인 + 사슬 검증
    a_in, a_out, b_in, b_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    s = srv.wrap_bio(a_in, a_out, server_side=True)
    c = cli.wrap_bio(b_in, b_out, server_hostname=host)
    for _ in range(20):
        done = 0
        for side in (c, s):
            try:
                side.do_handshake(); done += 1
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLCertVerificationError as e:
                return f"실패: {e.verify_message} (코드 {e.verify_code})"
            except ssl.SSLError as e:
                if side is s:   # 클라이언트가 끊으면 서버 쪽은 경보만 받는다
                    continue
                return f"실패: {e.reason}"
        a_in.write(b_out.read()); b_in.write(a_out.read())
        if done == 2:
            return f"통과 ({c.version()})"
    return "끝나지 않음"

if __name__ == "__main__":
    for name, chain, key, host, root in CASES:
        print(f"== {name}  (접속 이름 {host})")
        print(f"  cryptography : {by_cryptography(chain, host, root)}")
        print(f"  ssl 핸드셰이크: {by_ssl(chain, key, host, root)}")

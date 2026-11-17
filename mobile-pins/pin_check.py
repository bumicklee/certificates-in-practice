"""Network Security Config 의 pin-set 규칙을 흉내 내 사슬을 판정한다(학습용, Android 구현 아님).

    ../.venv/bin/python pin_check.py res/xml/network_security_config.xml out/current/chain.pem [YYYY-MM-DD]

규칙(공식 문서): 사슬 검증이 먼저 통과해야 하고, 검증된 사슬 안에 핀에 있는 공개키가 하나라도 있으면 통과.
expiration 날짜가 지나면 피닝은 꺼진다(사슬 검증만 남는다).
"""
import datetime as dt
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from compute_pins import spki_pin_from_public_key

HERE = Path(__file__).resolve().parent

def load_config(path):
    root = ET.parse(path).getroot()
    dc = root.find("domain-config")
    host = dc.find("domain").text.strip()
    ps = dc.find("pin-set")
    pins = {p.text.strip() for p in ps.findall("pin")}
    exp = dt.date.fromisoformat(ps.get("expiration")) if ps.get("expiration") else None
    anchor = HERE / "res/raw" / (dc.find("trust-anchors/certificates").get("src").split("/")[-1] + ".pem")
    return host, pins, exp, anchor

def judge(cfg, chain_file, today):
    host, pins, exp, anchor = load_config(cfg)
    certs = x509.load_pem_x509_certificates(Path(chain_file).read_bytes())
    store = Store(x509.load_pem_x509_certificates(anchor.read_bytes()))
    try:
        built = (PolicyBuilder().store(store).build_server_verifier(DNSName(host))
                 .verify(certs[0], certs[1:]))
    except VerificationError as e:
        return f"거부(사슬 검증 실패: {e})"
    chain_pins = [(c.subject.rfc4514_string(), spki_pin_from_public_key(c.public_key())) for c in built]
    if exp and today > exp:
        return f"통과(피닝 만료 {exp} 지남 → 사슬 검증만)"
    hit = [s for s, p in chain_pins if p in pins]
    if hit:
        return f"통과(핀 일치: {hit[0]})"
    return "거부(Pin verification failed: 사슬에 고정한 공개키가 없음)"

if __name__ == "__main__":
    cfg, chain = sys.argv[1], sys.argv[2]
    today = dt.date.fromisoformat(sys.argv[3]) if len(sys.argv) > 3 else dt.date.today()
    print(f"{chain}  (기준일 {today}) → {judge(cfg, chain, today)}")

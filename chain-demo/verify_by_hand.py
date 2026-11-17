"""사슬 검증을 손으로 한 단계씩 해 본다(5편). 실제 검증기는 이것 말고도
이름·용도·pathlen·폐기 등을 더 본다. 여기서는 '서명'과 '유효 기간'만 본다.

    ../.venv/bin/python verify_by_hand.py
"""
import datetime as dt
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

P = Path(__file__).resolve().parent.parent / "private-ca" / "out"
load = lambda n: x509.load_pem_x509_certificate((P / n).read_bytes())
leaf, inter, root = load("leaf.crt"), load("inter.crt"), load("root.crt")
now = dt.datetime.now(dt.timezone.utc)

def check(child, parent, label):
    ok_name = child.issuer == parent.subject
    try:
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                                   ec.ECDSA(child.signature_hash_algorithm))
        ok_sig = True
    except InvalidSignature:
        ok_sig = False
    ok_time = child.not_valid_before_utc <= now <= child.not_valid_after_utc
    bc = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
    print(f"{label:<14} issuer==subject:{ok_name}  서명:{ok_sig}  기간:{ok_time}  윗칸 CA:{bc.ca} pathlen:{bc.path_length}")

check(leaf, inter, "leaf <- inter")
check(inter, root, "inter <- root")
check(root, root, "root <- root")   # 루트는 자기 서명. 믿는 이유는 서명이 아니라 '저장소에 있어서'다

# 리프 바이트 하나를 바꾸면? (tbs 안의 일련번호 영역 한 바이트)
tbs = bytearray(leaf.tbs_certificate_bytes); tbs[20] ^= 0x01
try:
    inter.public_key().verify(leaf.signature, bytes(tbs), ec.ECDSA(leaf.signature_hash_algorithm))
    print("변조된 리프: 서명 통과(?)")
except InvalidSignature:
    print("변조된 리프(1바이트): 서명 실패 InvalidSignature")

# 엉뚱한 부모(루트)로 리프 서명을 확인하면?
try:
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    print("leaf <- root: 통과(?)")
except InvalidSignature:
    print("leaf <- root(중간 건너뜀): 서명 실패 InvalidSignature")

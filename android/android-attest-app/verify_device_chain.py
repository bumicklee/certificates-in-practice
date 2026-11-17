#!/usr/bin/env python3
"""내 Android 기기에서 받은 키 증명 사슬을 attestation/android-real 검증기(체크리스트 12줄)로 판정한다.
사용: ../../.venv/bin/python -I verify_device_chain.py <사슬.pem> <챌린지 hex 파일> <앱 서명 인증서 sha256 hex>
"""
import os
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[2] / "attestation" / "android-real"
sys.path.insert(0, str(LAB))
from cryptography import x509  # noqa: E402
import verify_real as v  # noqa: E402

pem, chfile, certhex = sys.argv[1], sys.argv[2], sys.argv[3]
chain = x509.load_pem_x509_certificates(open(pem, "rb").read())
challenge = bytes.fromhex(open(chfile).read().strip())
policy = dict(v.POLICY, packages={"lab.attest"}, signing_cert_sha256={bytes.fromhex(certhex)})
print(f"Google roots: {len(v.ROOTS)}, revocation entries: {len(v.STATUS)}, now={v.NOW:%Y-%m-%d}")
print(f"=== device chain ({os.path.basename(pem)})")
for i, c in enumerate(chain):
    print(f"  chain[{i}] {c.subject.rfc4514_string()[:60]:<60} {c.not_valid_before_utc:%Y-%m-%d}~{c.not_valid_after_utc:%Y-%m-%d}")
res, kd = v.check(chain, challenge, v.NOW, policy)
v.show_fields(kd, chain)
verdict = "ACCEPT" if all(ok for _, _, ok, _ in res) else "REJECT"
print(f"  -- checklist now ({v.NOW:%Y-%m-%d}) -> {verdict}")
for n, name, ok, why in sorted(res):
    print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")
print("=== negative: same chain, server expects a different (new) challenge")
for n, name, ok, why in v.check(chain, os.urandom(32), v.NOW, policy)[0]:
    if n == 6:
        print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")
print("=== negative: same chain, server policy expects com.example.shop")
for n, name, ok, why in v.check(chain, challenge, v.NOW, dict(policy, packages={"com.example.shop"}))[0]:
    if n == 10:
        print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")

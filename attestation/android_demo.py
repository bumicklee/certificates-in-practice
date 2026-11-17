#!/usr/bin/env python3
"""27편 Android식 키 증명: 가짜 기기 → 서버 검증. 루트 교체(옛 RSA 루트 + 새 P-384 루트)를 재현한다.
   ../.venv/bin/python android_demo.py
"""
import json, os
from cryptography import x509
from fakepki import NOW, ca_pair, cert, key, name, pem
from android_verifier import LAB_ATTEST_OID, REAL_ANDROID_OID, Reject, verify_attestation

# 가짜 Google 루트 두 개 (진짜 모양을 흉내: 옛 루트 RSA, 새 루트 ECDSA P-384)
OLD = ca_pair("FAKE Attestation Root OLD-RSA", "rsa")
NEW = ca_pair("FAKE Key Attestation CA1 NEW-P384", "p384")
ROGUE = ca_pair("FAKE Key Attestation CA1 NEW-P384", "p384")     # 이름만 같은 가짜 루트
SELF = ca_pair("Emulator Self-made Root", "p256")


class Device:
    """공장에서 받은 배치 증명 키(중간 CA)를 가진 기기. 실제로는 TEE/StrongBox 안에 있다."""
    def __init__(self, label, root):
        self.label, self.root = label, root
        self.batch = ca_pair(f"FAKE Attestation Batch ({label})", "p256", issuer=root, path_len=0)

    def attest(self, challenge, level="TrustedEnvironment", boot="Verified", locked=True):
        app_key = key("p256")      # 앱이 만든 키. 이 키가 '하드웨어 안에 있다'는 것을 증명받는다
        desc = {"attestationChallenge": challenge.hex(), "attestationSecurityLevel": level,
                "keymasterSecurityLevel": level, "rootOfTrust": {"verifiedBootState": boot, "deviceLocked": locked}}
        ext = x509.UnrecognizedExtension(LAB_ATTEST_OID, json.dumps(desc).encode())
        leaf = cert(name("Android Keystore Key"), app_key.public_key(), self.batch[0].subject, self.batch[1],
                    ca=False, days=365, exts=[ext])
        return pem(leaf) + pem(self.batch[0]) + pem(self.root[0])


def run(label, dev, roots, revoked=None, challenge_used=None, **kw):
    challenge = os.urandom(32)                        # 서버가 세션마다 새로 만든다
    chain = dev.attest(challenge_used or challenge, **kw)
    try:
        r = verify_attestation(chain, challenge, [c for c, _ in roots], revoked or {}, NOW)
        print(f"PASS  {label:<52} root={r['root']!r} level={r['securityLevel']}")
    except Reject as e:
        print(f"FAIL  {label:<52} {e}")


print(f"(실제 Android 증명 확장 OID {REAL_ANDROID_OID}; 실습 확장 OID {LAB_ATTEST_OID.dotted_string})")
old_dev, new_dev = Device("2024 phone", OLD), Device("2026 phone", NEW)
both = [OLD, NEW]
print("\n# 서버 신뢰 목록 = [옛 루트, 새 루트]")
run("old-root device", old_dev, both)
run("new-root device", new_dev, both)
run("unknown root (self-made / emulator)", Device("emulator", SELF), both)
run("root with same NAME as new root, different key", Device("spoof", ROGUE), both)
run("wrong nonce (replayed answer from old session)", new_dev, both, challenge_used=os.urandom(32))
run("key in software only", new_dev, both, level="Software")
run("unlocked bootloader", new_dev, both, boot="Unverified", locked=False)
rev = {"entries": {format(old_dev.batch[0].serial_number, "x"): {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}
run("old-root device, batch key revoked in status list", old_dev, both, revoked=rev)
print("\n# 서버 신뢰 목록 = [옛 루트] 만 (새 루트를 안 넣은 서버)")
run("old-root device", old_dev, [OLD])
run("new-root device", new_dev, [OLD])

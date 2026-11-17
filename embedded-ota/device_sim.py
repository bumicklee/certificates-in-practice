#!/usr/bin/env python3
"""보일러 컨트롤러 기기 시뮬레이터 (24편).

기기 안에 있는 것
  (a) 루트 묶음        : 활성 슬롯 이미지 안에 들어 있다(ESP-IDF 인증서 번들처럼 앱과 함께 OTA로 바뀐다)
  (b) OTA 서명 공개키  : device/<이름>/ota_pub.pem (공장에서 넣는다. 서명 개인키는 기기에 없다)
  (c) 보안 버전 하한   : state.json min_security_version (eFuse처럼 올라가기만 한다)
  (d) 시각 하한        : state.json build_time_floor (RTC가 없을 때 '최소한 이 시각 이후'로 본다)

명령
  factory  --dev D --fw NAME          공장 출고(슬롯 A에 굽기)
  status   --dev D
  ota      --dev D --fw NAME          OTA 받기 → 검증 → 비활성 슬롯에 쓰기 → 재부팅 → 자체 시험 → 확정/되돌리기
  connect  --dev D --port P           127.0.0.1:P 서버에 TLS 접속(SNI api.boiler.lab.example)
  checktime --dev D --chain F --clock ISO|1970 --policy naive|floor|unsynced
"""
import argparse, base64, datetime as dt, hashlib, json, os, shutil, socket, ssl, sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.join(HERE, "out/fw")
SNI = "api.boiler.lab.example"


def ddir(dev): return os.path.join(HERE, "device", dev)
def load(dev): return json.load(open(os.path.join(ddir(dev), "state.json")))
def save(dev, s): json.dump(s, open(os.path.join(ddir(dev), "state.json"), "w"), indent=2)
def other(slot): return "B" if slot == "A" else "A"
def iso(s): return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def bundle_of(image: bytes) -> bytes:
    a = image.index(b"-----CA-BUNDLE-----\n") + len(b"-----CA-BUNDLE-----\n")
    return image[a:image.index(b"-----END-CA-BUNDLE-----")]


def verify_manifest(dev, man: dict, image: bytes):
    """서명 → 해시 → 보안 버전 순. 서명이 맞기 전에는 매니페스트의 어떤 값도 믿지 않는다."""
    pub = serialization.load_pem_public_key(open(os.path.join(ddir(dev), "ota_pub.pem"), "rb").read())
    body = {k: v for k, v in man.items() if k != "signature"}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    try:
        pub.verify(base64.b64decode(man["signature"]), payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "REJECT signature: 기기의 OTA 공개키로 매니페스트 서명이 검증되지 않음"
    print("  [1] 서명 OK (ECDSA P-256 / SHA-256, 기기 내장 공개키)")
    if len(image) != man["size"] or hashlib.sha256(image).hexdigest() != man["sha256"]:
        return f"REJECT sha256: 이미지 해시 {hashlib.sha256(image).hexdigest()[:16]}… ≠ 매니페스트 {man['sha256'][:16]}…"
    print(f"  [2] 이미지 해시 OK sha256={man['sha256'][:16]}…")
    s = load(dev)
    if man["security_version"] < s["min_security_version"]:
        return (f"REJECT rollback: security_version {man['security_version']} < "
                f"기기 하한 {s['min_security_version']} (version {man['version']})")
    print(f"  [3] 보안 버전 OK {man['security_version']} >= 하한 {s['min_security_version']}")
    return None


def cmd_factory(a):
    d = ddir(a.dev)
    if os.path.exists(d): shutil.rmtree(d)
    os.makedirs(d)
    shutil.copy(os.path.join(HERE, "out/ota/ota_sign.pub"), os.path.join(d, "ota_pub.pem"))
    man = json.load(open(os.path.join(FW, a.fw + ".manifest.json")))
    image = open(os.path.join(FW, a.fw + ".bin"), "rb").read()
    save(a.dev, {"active": "A", "slots": {"A": None, "B": None}, "min_security_version": 0,
                 "build_time_floor": "1970-01-01T00:00:00Z"})
    err = verify_manifest(a.dev, man, image)
    if err: sys.exit(err)
    open(os.path.join(d, "slot_A.bin"), "wb").write(image)
    json.dump(man, open(os.path.join(d, "slot_A.manifest.json"), "w"))
    save(a.dev, {"active": "A", "slots": {"A": man["version"], "B": None},
                 "min_security_version": man["security_version"], "build_time_floor": man["build_time"]})
    print(f"factory: {a.dev} slot A = {man['version']} (sv {man['security_version']})")
    cmd_status(a)


def cmd_status(a):
    s = load(a.dev)
    img = open(os.path.join(ddir(a.dev), f"slot_{s['active']}.bin"), "rb").read()
    roots = [x509.load_pem_x509_certificate(b"-----BEGIN" + p) for p in bundle_of(img).split(b"-----BEGIN")[1:]]
    names = ", ".join(r.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value for r in roots)
    print(f"status {a.dev}: active={s['active']} slots={s['slots']} min_security_version={s['min_security_version']} "
          f"build_time_floor={s['build_time_floor']}\n  roots in active image: [{names}]")


def cmd_ota(a):
    s = load(a.dev)
    man = json.load(open(os.path.join(FW, a.fw + ".manifest.json")))
    image = open(os.path.join(FW, a.fw + ".bin"), "rb").read()
    print(f"ota {a.dev}: offered {a.fw} (version {man['version']}, sv {man['security_version']})")
    err = verify_manifest(a.dev, man, image)
    if err:
        print("  " + err + f"\n  → 아무것도 쓰지 않음. 활성 슬롯 {s['active']} 그대로"); return 1
    tgt, prev = other(s["active"]), s["active"]
    open(os.path.join(ddir(a.dev), f"slot_{tgt}.bin"), "wb").write(image)
    json.dump(man, open(os.path.join(ddir(a.dev), f"slot_{tgt}.manifest.json"), "w"))
    print(f"  [4] 비활성 슬롯 {tgt}에 기록, 상태 PENDING_VERIFY, 재부팅")
    # 재부팅: 부트로더가 다시 해시를 본다(보안 부팅이 하는 일의 흉내)
    if hashlib.sha256(open(os.path.join(ddir(a.dev), f"slot_{tgt}.bin"), "rb").read()).hexdigest() != man["sha256"]:
        print("  boot: 슬롯 해시 불일치 → 이전 슬롯으로"); return 1
    if b"-----SELFTEST:ok-----" not in image:
        print(f"  [5] 자체 시험 실패(서버 접속·센서 확인 실패 가정) → 롤백, 활성 슬롯 {prev} 유지")
        s["slots"][tgt] = None; save(a.dev, s); cmd_status(a); return 1
    s["active"] = tgt; s["slots"][tgt] = man["version"]
    old_sv = s["min_security_version"]
    s["min_security_version"] = max(old_sv, man["security_version"])
    s["build_time_floor"] = max(s["build_time_floor"], man["build_time"])
    save(a.dev, s)
    print(f"  [5] 자체 시험 OK → 슬롯 {tgt} 확정(이전 슬롯 {prev}는 예비). 보안 버전 하한 {old_sv} → {s['min_security_version']}")
    cmd_status(a)


def cmd_connect(a):
    s = load(a.dev)
    img = open(os.path.join(ddir(a.dev), f"slot_{s['active']}.bin"), "rb").read()
    ctx = ssl.create_default_context(cadata=bundle_of(img).decode())   # 시스템 저장소 대신 기기 묶음만
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection(("127.0.0.1", a.port), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=SNI) as t:
                t.sendall(b"hello\n")
                print(f"connect {a.dev} → 127.0.0.1:{a.port}: OK {t.version()} server says: {t.recv(200).decode().strip()}")
    except ssl.SSLCertVerificationError as e:
        print(f"connect {a.dev} → 127.0.0.1:{a.port}: FAIL {e.verify_message} (verify code {e.verify_code})")
        return 1


def cmd_checktime(a):
    s = load(a.dev)
    img = open(os.path.join(ddir(a.dev), f"slot_{s['active']}.bin"), "rb").read()
    roots = [x509.load_pem_x509_certificate(b"-----BEGIN" + p) for p in bundle_of(img).split(b"-----BEGIN")[1:]]
    certs = x509.load_pem_x509_certificates(open(a.chain, "rb").read())
    clock = iso(a.clock if a.clock != "1970" else "1970-01-01T00:00:10Z")
    floor = iso(s["build_time_floor"])
    if a.policy == "naive" or clock >= floor:
        t = clock                                   # 시각을 안다(또는 그렇다고 믿는다)
    elif a.policy == "floor":
        t = floor                                   # 시각을 모르면 빌드 시각으로
    else:  # unsynced: 시각을 모르면 notBefore는 넘기되, 빌드 시각 이전에 만료된 것은 거부
        t = max(floor, certs[0].not_valid_before_utc)
    note = "" if t == clock else f" (floor {s['build_time_floor']} → 검사 시각 {t:%Y-%m-%dT%H:%M:%SZ})"
    v = PolicyBuilder().store(Store(roots)).time(t).build_server_verifier(x509.DNSName(SNI))
    try:
        v.verify(certs[0], certs[1:])
        print(f"checktime {a.dev} clock={clock:%Y-%m-%dT%H:%M:%SZ} policy={a.policy}{note}: OK "
              f"(leaf notBefore {certs[0].not_valid_before_utc:%Y-%m-%dT%H:%M:%SZ})")
    except VerificationError as e:
        print(f"checktime {a.dev} clock={clock:%Y-%m-%dT%H:%M:%SZ} policy={a.policy}{note}: FAIL {e}")
        return 1


def main():
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    for n in ["factory", "status", "ota", "connect", "checktime"]:
        p = sp.add_parser(n); p.add_argument("--dev", required=True)
        if n in ("factory", "ota"): p.add_argument("--fw", required=True)
        if n == "connect": p.add_argument("--port", type=int, required=True)
        if n == "checktime":
            p.add_argument("--chain", required=True); p.add_argument("--clock", required=True)
            p.add_argument("--policy", choices=["naive", "floor", "unsynced"], default="floor")
    a = ap.parse_args()
    return globals()["cmd_" + a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())

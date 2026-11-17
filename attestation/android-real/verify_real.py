#!/usr/bin/env python3
"""27·28편: 실제 Android 기기에서 나온 공개 시험용 증명 사슬을 읽고 서버 검증 체크리스트를 돌린다.

  ../../.venv/bin/python -I verify_real.py            # 4개 사슬 전부
  ../../.venv/bin/python -I verify_real.py --fields   # KeyDescription 필드도 출력

데이터(읽기만 해서 받은 것)
  data/    android/keyattestation 저장소 testdata (Apache-2.0)
  google/  https://android.googleapis.com/attestation/root, /status
"""
import base64, datetime as dt, glob, hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # -I 로 돌려도 옆의 keydesc.py 를 쓰도록
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from keydesc import KEYDESC_OID, PROVINFO_OID, PURPOSE, ALGORITHM, ORIGIN, parse_key_description

HERE = os.path.dirname(os.path.abspath(__file__))
NOW = dt.datetime.now(dt.timezone.utc)

# ---- 서버 정책 (서비스가 정한다. 아래 값은 예) ---------------------------------
POLICY = {
    "levels": {"TrustedEnvironment", "StrongBox"},
    "min_os_patch": 202510,                      # 최근 12개월 패치(2026-10 기준)
    # 이 시험 데이터를 만든 Google 수집 앱 두 개. 실서비스는 내 앱 패키지 하나와 내 서명 인증서 SHA-256
    "packages": {"com.google.android.attestation",
                 "com.google.wireless.android.security.attestationverifier.collector"},
    "signing_cert_sha256": {base64.b64decode("EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE=")},
}


def spki(c):
    return c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_json_with_comments(path):
    return json.loads("\n".join(l for l in open(path) if not l.lstrip().startswith("//")))


ROOTS = [x509.load_pem_x509_certificate(p.encode()) for p in json.load(open(f"{HERE}/google/roots.json"))]
STATUS = json.load(open(f"{HERE}/google/status.json"))["entries"]


def check(chain, expected_challenge, at, policy=POLICY):
    """체크리스트. [(번호, 이름, 통과?, 설명)] 을 돌려준다. 하나라도 False면 거부."""
    r = []
    # 1) 사슬 서명: 각 인증서가 바로 위 인증서로 서명됐나
    try:
        for child, parent in zip(chain, chain[1:]):
            child.verify_directly_issued_by(parent)
        r.append((1, "chain signatures", True, f"{len(chain)} certs"))
    except Exception as e:
        r.append((1, "chain signatures", False, str(e)))
    # 2) 루트: Google 루트 목록과 '공개키'로 비교 (같은 키로 다시 만든 루트 인증서가 여럿 있다)
    root = chain[-1]
    hit = [i for i, g in enumerate(ROOTS) if spki(g) == spki(root)]
    r.append((2, "root pubkey in Google list", bool(hit),
              f"roots.json[{hit[0]}] {ROOTS[hit[0]].subject.rfc4514_string()}" if hit else root.subject.rfc4514_string()))
    # 3) 폐기 목록: 사슬의 모든 일련번호(소문자 16진수)
    bad = [format(c.serial_number, "x") for c in chain if format(c.serial_number, "x") in STATUS]
    r.append((3, "not in revocation list", not bad, f"{len(STATUS)} entries checked" if not bad else f"revoked {bad}"))
    # 4) 유효 기간: RKP 사슬(프로비저닝 정보 확장 있음)은 꼭 본다. 2021년 전 공장 키는 문서가 '기간 무시' 허용
    prov_idx = next((i for i in range(len(chain) - 1, -1, -1)
                     if _has(chain[i], PROVINFO_OID)), None)
    if prov_idx is not None:
        expired = [c.subject.rfc4514_string() for c in chain[1:]
                   if not (c.not_valid_before_utc <= at <= c.not_valid_after_utc)]
        r.append((4, "RKP certs valid at time", not expired, f"at {at:%Y-%m-%d}" + (f" expired: {expired[0]}" if expired else "")))
    else:
        r.append((4, "validity (factory chain)", True, "factory-provisioned: validity not enforced (per Android doc)"))
    # 5) 확장 위치: 루트 쪽에서 처음 나오는 것만 믿는다. 프로비저닝 정보가 있으면 바로 다음 인증서여야 한다
    first = next((i for i in range(len(chain) - 1, -1, -1) if _has(chain[i], KEYDESC_OID)), None)
    ok5 = first is not None and (prov_idx is None or first == prov_idx - 1)
    r.append((5, "KeyDescription position", ok5, f"chain[{first}]" + (f", provisioning info chain[{prov_idx}]" if prov_idx is not None else "")))
    if first is None:
        return r, None
    kd = parse_key_description(chain[first].extensions.get_extension_for_oid(KEYDESC_OID).value.value)
    hw, sw = kd["hardwareEnforced"], kd["softwareEnforced"]
    # 6) 챌린지
    r.append((6, "challenge matches", kd["attestationChallenge"] == expected_challenge,
              f"{len(kd['attestationChallenge'])} bytes"))
    # 6b) 챌린지 길이: AOSP 문서는 16바이트 이상의 nonce를 권한다
    r.append((12, "challenge >= 16 bytes", len(kd["attestationChallenge"]) >= 16, repr(kd["attestationChallenge"][:12]) + "…"))
    # 7) 보안 수준
    lv = (kd["attestationSecurityLevel"], kd["keyMintSecurityLevel"])
    r.append((7, "security level is hardware", all(x in policy["levels"] for x in lv), "/".join(lv)))
    # 8) 부팅 상태
    rot = hw.get("rootOfTrust", {})
    r.append((8, "verified boot + locked", rot.get("verifiedBootState") == "Verified" and rot.get("deviceLocked") is True,
              f"{rot.get('verifiedBootState')}, locked={rot.get('deviceLocked')}"))
    # 9) 패치 수준
    pl = hw.get("osPatchLevel", 0)
    r.append((9, f"osPatchLevel >= {policy['min_os_patch']}", pl >= policy["min_os_patch"], str(pl)))
    # 10) 앱: 패키지 이름 + 서명 인증서 SHA-256 (softwareEnforced 쪽에 들어 있다)
    app = sw.get("attestationApplicationId") or hw.get("attestationApplicationId") or {"packages": [], "signatureDigests": []}
    names = {p for p, _ in app["packages"]}
    ok10 = bool(names & policy["packages"]) and set(app["signatureDigests"]) <= policy["signing_cert_sha256"] and app["signatureDigests"]
    r.append((10, "app package + signing cert", bool(ok10), f"{sorted(names)[0] if names else '-'} digest {app['signatureDigests'][0].hex()[:12]}…" if app["signatureDigests"] else "none"))
    # 11) 키 속성: 하드웨어 쪽에서 강제되는 값으로 본다
    ok11 = 2 in hw.get("purpose", []) and hw.get("algorithm") in (1, 3) and hw.get("origin") == 0
    r.append((11, "key: SIGN, RSA/EC, GENERATED (hw)", ok11,
              f"purpose={[PURPOSE.get(p, p) for p in hw.get('purpose', [])]} alg={ALGORITHM.get(hw.get('algorithm'))} origin={ORIGIN.get(hw.get('origin'))}"))
    return r, kd


def _has(c, oid):
    try:
        c.extensions.get_extension_for_oid(oid); return True
    except x509.ExtensionNotFound:
        return False


def show_fields(kd, chain):
    hw, sw = kd["hardwareEnforced"], kd["softwareEnforced"]
    print(f"  attestationVersion={kd['attestationVersion']} keyMintVersion={kd['keyMintVersion']}")
    print(f"  attestationSecurityLevel={kd['attestationSecurityLevel']} keyMintSecurityLevel={kd['keyMintSecurityLevel']}")
    print(f"  attestationChallenge={kd['attestationChallenge']!r}")
    print(f"  uniqueId={kd['uniqueId'].hex() or '(empty)'}")
    for label, al in (("softwareEnforced", sw), ("hardwareEnforced", hw)):
        print(f"  {label}:")
        for k, v in al.items():
            if k == "rootOfTrust":
                v = {kk: (vv.hex()[:16] + "…" if isinstance(vv, bytes) else vv) for kk, vv in v.items()}
            elif k == "attestationApplicationId":
                v = {"packages": v["packages"], "signatureDigests": [d.hex()[:16] + "…" for d in v["signatureDigests"]]}
            elif k == "creationDateTime":
                v = f"{v} ({dt.datetime.fromtimestamp(v / 1000, dt.timezone.utc):%Y-%m-%d %H:%M} UTC)"
            elif isinstance(v, bytes):
                v = v.hex()[:16] + "…"
            print(f"    {k:<26} {v}")
    for c in chain:
        if _has(c, PROVINFO_OID):
            print(f"  provisioningInfo (CBOR, {PROVINFO_OID.dotted_string}) = "
                  f"{cbor2.loads(c.extensions.get_extension_for_oid(PROVINFO_OID).value.value)}")


def run(path, fields):
    chain = x509.load_pem_x509_certificates(open(path, "rb").read())
    exp = load_json_with_comments(path[:-4] + ".json")
    challenge = base64.b64decode(exp["attestationChallenge"])
    created = dt.datetime.fromtimestamp(int(exp["softwareEnforced"]["creationDateTime"]) / 1000, dt.timezone.utc)
    print(f"\n=== {os.path.basename(path)}")
    for i, c in enumerate(chain):
        print(f"  chain[{i}] {c.subject.rfc4514_string()[:60]:<60} {c.not_valid_before_utc:%Y-%m-%d}~{c.not_valid_after_utc:%Y-%m-%d}")
    for label, at in (("at capture time", created), ("now", NOW)):
        res, kd = check(chain, challenge, at)
        if fields and label == "now":
            show_fields(kd, chain)
        verdict = "ACCEPT" if all(ok for _, _, ok, _ in res) else "REJECT"
        print(f"  -- checklist {label} ({at:%Y-%m-%d}) -> {verdict}")
        for n, name, ok, why in sorted(res):
            print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")
    return chain, challenge, created


if __name__ == "__main__":
    fields = "--fields" in sys.argv
    print(f"Google roots: {len(ROOTS)}, revocation entries: {len(STATUS)}, now={NOW:%Y-%m-%d}")
    files = sorted(glob.glob(f"{HERE}/data/*.pem"))
    last = None
    for f in files:
        last = run(f, fields)
    # 일부러 틀린 값 두 가지: 다른 세션의 챌린지, 다른 앱 정책
    chain, challenge, created = last
    print("\n=== negative: same chain, server expects a different (new) challenge")
    for n, name, ok, why in check(chain, os.urandom(32), created)[0]:
        if n == 6: print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")
    print("=== negative: same chain, server policy expects com.example.shop")
    other = dict(POLICY, packages={"com.example.shop"})
    for n, name, ok, why in check(chain, challenge, created, other)[0]:
        if n == 10: print(f"    {n:>2} {'PASS' if ok else 'FAIL'}  {name:<36} {why}")

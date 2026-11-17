"""30편 실습: .well-known 점검 스크립트.

  python check.py https://localhost:18492 --cert keys/app-signing.crt --package example.lab.shop

TLS는 공용 사설 CA 루트로 검증한다(--ca). 리다이렉트는 따라가지 않는다(앱 링크 검증기도 따라가지 않는다).
"""
import argparse, datetime as dt, json, re, sys, urllib.parse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

ap = argparse.ArgumentParser()
ap.add_argument("base"); ap.add_argument("--cert", required=True); ap.add_argument("--package", required=True)
ap.add_argument("--ca", default="../private-ca/out/ca-bundle.pem")
a = ap.parse_args()
cli = httpx.Client(base_url=a.base, verify=a.ca, follow_redirects=False, timeout=5)
fails = 0


def res(ok, name, msg):
    global fails
    fails += 0 if ok else 1
    print(f"  [{'OK' if ok else 'FAIL'}] {name}: {msg}")


def get_json(name, path, ctype="application/json"):
    r = cli.get(path)
    if r.status_code != 200:
        res(False, name, f"HTTP {r.status_code} (리다이렉트 없이 200이어야 함)"); return None
    ct = r.headers.get("content-type", "")
    res(ct.split(";")[0].strip() == ctype, name + " Content-Type", ct)
    try:
        return r.json()
    except Exception as e:
        res(False, name, f"JSON 아님: {e}"); return None


c = x509.load_pem_x509_certificate(open(a.cert, "rb").read())
want = ":".join(f"{b:02X}" for b in c.fingerprint(hashes.SHA256()))
print(f"점검 대상 {a.base}\n앱 서명 인증서 SHA-256 = {want}\n")

print("assetlinks.json (Android 앱 링크)")
j = get_json("assetlinks", "/.well-known/assetlinks.json")
if j is not None:
    fps = [f for st in j if st.get("target", {}).get("package_name") == a.package
           for f in st["target"].get("sha256_cert_fingerprints", [])]
    res(bool(fps), "패키지", f"{a.package} 항목 {len(fps)}개 지문")
    res(want in fps, "지문 일치", "서명 인증서와 같음" if want in fps else f"올라간 지문 {fps[0][:23]}... ≠ 서명 인증서")

print("apple-app-site-association (iOS 유니버설 링크)")
j = get_json("AASA", "/.well-known/apple-app-site-association")
if j is not None:
    ids = [i for d in j.get("applinks", {}).get("details", []) for i in d.get("appIDs", [])]
    res(all(re.fullmatch(r"[A-Z0-9]{10}\.[\w.\-]+", i) for i in ids) and ids, "appIDs", ", ".join(ids))

print("openid-configuration + JWKS")
j = get_json("openid-configuration", "/.well-known/openid-configuration")
if j is not None:
    res(j.get("issuer") == a.base, "issuer", f"{j.get('issuer')} (가져온 주소와 정확히 같아야 함)")
    ju = j.get("jwks_uri", "")
    res(urllib.parse.urlsplit(ju).scheme == "https", "jwks_uri", ju)
    k = get_json("jwks", urllib.parse.urlsplit(ju).path)
    if k is not None:
        PRIV = {"d", "p", "q", "dp", "dq", "qi", "k"}
        for key in k.get("keys", []):
            leaked = sorted(PRIV & key.keys())
            res(not leaked, f"키 {key.get('kid')}",
                f"kty={key.get('kty')} alg={key.get('alg')}" + (f" / 개인키 필드 {leaked} 있음! 키 폐기·교체" if leaked else " / 공개 필드만"))

print("security.txt (RFC 9116)")
r = cli.get("/.well-known/security.txt")
if r.status_code == 200:
    res(r.headers.get("content-type", "").startswith("text/plain"), "Content-Type", r.headers.get("content-type"))
    t = r.text
    res(bool(re.search(r"^Contact:", t, re.M)), "Contact", "있음" if re.search(r"^Contact:", t, re.M) else "없음")
    ex = re.findall(r"^Expires:\s*(\S+)", t, re.M)
    if len(ex) != 1:
        res(False, "Expires", f"{len(ex)}개 (정확히 1개여야 함)")
    else:
        e = dt.datetime.fromisoformat(ex[0].replace("Z", "+00:00"))
        days = (e - dt.datetime.now(dt.timezone.utc)).days
        res(0 < days, "Expires", f"{ex[0]} ({days}일 남음)" + (" / 1년 넘게 남음, 1년 안쪽 권장" if days > 365 else ""))
    canon = re.findall(r"^Canonical:\s*(\S+)", t, re.M)
    res(a.base + "/.well-known/security.txt" in canon, "Canonical", ", ".join(canon))
else:
    res(False, "security.txt", f"HTTP {r.status_code}")

print("change-password")
r = cli.get("/.well-known/change-password")
res(r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers, "리다이렉트",
    f"HTTP {r.status_code} -> {r.headers.get('location')}")

print("webauthn (관련 출처 요청)")
j = get_json("webauthn", "/.well-known/webauthn")
if j is not None:
    origins = j.get("origins", [])
    res(all(o.startswith("https://") for o in origins) and origins, "origins", ", ".join(origins))
    # 등록 가능한 도메인의 첫 라벨 수(브라우저 최소 지원 5). 여기선 *.lab.example을 하나의 공개 접미사처럼 다룬다.
    labels = {urllib.parse.urlsplit(o).hostname.removesuffix(".co.kr").removesuffix(".lab.example").split(".")[-1]
              for o in origins}
    res(len(labels) <= 5, "라벨 수", f"{len(labels)}개 {sorted(labels)} (5개 이하 권장)")

print(f"\n결과: 실패 {fails}건")
sys.exit(1 if fails else 0)

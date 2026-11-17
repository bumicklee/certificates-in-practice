"""HSTS 헤더와 HTTP→HTTPS 이동을 보고 hstspreload.org 제출 조건을 점검한다(로컬 서버 전용).

    ../.venv/bin/python check_hsts.py                       # ./run.sh start 로 띄운 서버
    ../.venv/bin/python check_hsts.py --header "max-age=300"   # 헤더 문자열만 따져 보기(접속 안 함)

조건 출처: https://hstspreload.org/ (Submission Requirements)
"""
import argparse
from pathlib import Path

import httpx

CA = Path(__file__).resolve().parent.parent / "private-ca/out/ca-bundle.pem"
ONE_YEAR = 31536000

def parse(value: str):
    d = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition("=")
        d[k.strip().lower()] = v.strip().strip('"')
    return d

def check_header(value):
    d = parse(value)
    age = int(d.get("max-age", "0") or 0)
    rows = [
        (f"max-age ≥ {ONE_YEAR}(1년)", age >= ONE_YEAR, f"max-age={age}"),
        ("includeSubDomains", "includesubdomains" in d, ""),
        ("preload", "preload" in d, ""),
    ]
    return rows

def show(rows):
    ok = True
    for name, passed, note in rows:
        ok &= passed is True
        mark = {True: "통과", False: "실패", None: "확인 불가"}[passed]
        print(f"  [{mark}] {name}" + (f"  ({note})" if note else ""))
    return ok

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--https", default="https://localhost:18450/")
    ap.add_argument("--http", default="http://localhost:18451/")
    ap.add_argument("--header", help="접속하지 않고 이 헤더 값만 점검")
    a = ap.parse_args()

    if a.header:
        print(f"헤더만 점검: {a.header}")
        ok = show(check_header(a.header))
        print("preload 조건:", "충족" if ok else "미충족")
        raise SystemExit(0 if ok else 1)

    rows = []
    with httpx.Client(verify=str(CA), follow_redirects=False, timeout=5) as c:
        r = c.get(a.https)
        sts = r.headers.get("strict-transport-security")
        print(f"HTTPS {a.https} → {r.status_code}")
        print(f"  Strict-Transport-Security: {sts}")
        rows.append(("유효한 인증서로 HTTPS 응답", True, "로컬 사설 CA 기준. 실제 제출은 공개 CA 인증서여야 한다"))
        rows += check_header(sts or "")

        h = c.get(a.http)
        loc = h.headers.get("location", "")
        print(f"HTTP  {a.http} → {h.status_code} Location: {loc}")
        same_host = httpx.URL(loc).host == httpx.URL(a.http).host if loc else False
        rows.append(("HTTP는 같은 호스트의 HTTPS로 이동", h.status_code in (301, 308) and loc.startswith("https://") and same_host,
                     f"{h.status_code} → {loc}"))
        rows.append(("HTTP 응답의 HSTS는 무시된다(있어도 효과 없음)", True,
                     "있음" if "strict-transport-security" in h.headers else "없음"))
    rows.append(("모든 하위 도메인이 HTTPS", None, "운영 중인 하위 도메인 목록으로 직접 확인"))
    show(rows)
    fails = sum(1 for r in rows if r[1] is False); unknown = sum(1 for r in rows if r[1] is None)
    print(f"결과: 실패 {fails}건, 직접 확인 {unknown}건" + (" → 로컬에서 볼 수 있는 조건은 모두 충족" if fails == 0 else ""))
    raise SystemExit(1 if fails else 0)

"""공개 CT 검색(읽기 전용): crt.sh 에서 한 도메인의 인증서 목록을 받아 lab/results 에 저장한다.

    ../.venv/bin/python ct_search.py example.com            # 캐시가 있으면 캐시를 쓴다(요청 0회)
    ../.venv/bin/python ct_search.py example.com --refresh  # 새로 받는다(요청 1회, 실패하면 15초 뒤 1회만 다시)

- crt.sh 는 무료 공익 서비스다. 자주 부르지 않는다. 감시는 하루 1~2회면 충분하다.
- 내 도메인 또는 문서용 도메인(example.com)에만 쓴다.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import httpx

RESULTS = Path(__file__).resolve().parent.parent / "results"

def cache_path(domain):
    return RESULTS / f"15-crtsh-{domain}.json"

def fetch(domain):
    url = "https://crt.sh/"
    params = {"q": domain, "output": "json", "exclude": "expired"}
    headers = {"User-Agent": "pki-chains-lab/1.0 (read-only CT search; one request)"}
    for attempt in (1, 2):
        try:
            r = httpx.get(url, params=params, headers=headers, timeout=90)
            print(f"요청 {attempt}: {r.url} → HTTP {r.status_code}, {len(r.content)}바이트", file=sys.stderr)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            print(f"요청 {attempt} 실패: {type(e).__name__}: {e}", file=sys.stderr)
            if attempt == 1:
                time.sleep(15)
    return None

def load(domain, refresh=False):
    p = cache_path(domain)
    if p.exists() and not refresh:
        print(f"캐시 사용: {p.name} (요청 0회)", file=sys.stderr)
        return json.loads(p.read_text())
    data = fetch(domain)
    if data is None:
        if p.exists():
            print("crt.sh 응답 없음 → 이전 캐시를 쓴다", file=sys.stderr)
            return json.loads(p.read_text())
        sys.exit("crt.sh 응답 없음, 캐시도 없음")
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    return data

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain"); ap.add_argument("--refresh", action="store_true")
    a = ap.parse_args()
    rows = load(a.domain, a.refresh)
    print(f"{a.domain}: 만료 안 된 CT 항목 {len(rows)}건 (사전 인증서·인증서가 따로 잡힐 수 있다)")
    rows.sort(key=lambda r: (r.get("not_before", ""), r["id"]), reverse=True)
    print(f"{'crt.sh id':>12}  {'유효 시작(UTC)':19}  {'만료':10}  일련번호 앞 8자  발급자 · 이름")
    for r in rows[:20]:
        issuer = r["issuer_name"].split("CN=")[-1]
        names = r["name_value"].replace("\n", ", ")
        print(f"{r['id']:>12}  {r['not_before'][:19]:19}  {r['not_after'][:10]}  {r['serial_number'][:8]}        {issuer} · {names}")

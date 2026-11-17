"""새 발급 알림: CT 검색 결과를 로컬 상태 파일과 비교해 처음 보는 인증서만 알린다.

    ../.venv/bin/python ct_watch.py example.com --expect-issuer "Sectigo" --seed-before 2026-09-01
    ../.venv/bin/python ct_watch.py example.com --expect-issuer "Sectigo"     # 다시 돌리면 새 항목 0건

- 데이터는 ct_search.py 의 캐시(lab/results/15-crtsh-<도메인>.json)를 쓴다. --refresh 를 주면 crt.sh 에 1회 요청.
- 같은 일련번호·발급자는 하나로 묶는다(사전 인증서와 최종 인증서가 둘 다 로그에 오른다).
- --seed-before: 상태 파일이 없을 때, 이 날짜 이전 항목은 "이미 본 것"으로 기준선을 만든다(첫 실행 데모용).
- 알림 규칙: ① 처음 본 인증서 ② 기대한 발급자가 아님 ③ 이름에 와일드카드 ④ 모르는 이름
"""
import argparse
import json
from pathlib import Path

from ct_search import load

STATE_DIR = Path(__file__).resolve().parent / "state"

def key(r):
    return f"{r['issuer_ca_id']}:{r['serial_number']}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--expect-issuer", action="append", default=[], help="발급자 이름에 들어 있어야 할 문자열(여러 번)")
    ap.add_argument("--expect-name", action="append", default=[], help="알려진 이름(없으면 도메인과 www)")
    ap.add_argument("--seed-before", help="YYYY-MM-DD")
    ap.add_argument("--refresh", action="store_true")
    a = ap.parse_args()

    rows = load(a.domain, a.refresh)
    groups = {}
    for r in rows:
        groups.setdefault(key(r), r)
    STATE_DIR.mkdir(exist_ok=True)
    sp = STATE_DIR / f"{a.domain}.json"
    if sp.exists():
        seen = set(json.loads(sp.read_text())["seen"])
        print(f"상태 파일: {sp.name} (이미 본 인증서 {len(seen)}장)")
    else:
        seen = {k for k, r in groups.items() if a.seed_before and r["not_before"][:10] < a.seed_before}
        print(f"상태 파일 없음 → 기준선 생성: {a.seed_before} 이전 {len(seen)}장을 '이미 본 것'으로")

    known = set(a.expect_name or [a.domain, f"www.{a.domain}"])
    new = [(k, r) for k, r in groups.items() if k not in seen]
    print(f"CT 항목 {len(rows)}건 → 인증서 {len(groups)}장(일련번호 기준), 새로 본 것 {len(new)}장")
    for k, r in sorted(new, key=lambda x: x[1]["not_before"]):
        names = sorted(set(r["name_value"].split("\n")))
        issuer = r["issuer_name"].split("CN=")[-1]
        flags = []
        if a.expect_issuer and not any(e in r["issuer_name"] for e in a.expect_issuer):
            flags.append("기대한 발급자 아님")
        if any(n.startswith("*.") for n in names):
            flags.append("와일드카드")
        odd = [n for n in names if n not in known and not n.startswith("*.")]
        if odd:
            flags.append("모르는 이름: " + ", ".join(odd))
        print(f"  [알림] {r['not_before'][:10]}  {issuer}  일련번호 {r['serial_number'][:12]}…  {', '.join(names)}")
        print(f"         https://crt.sh/?id={r['id']}  " + (" / ".join(flags) if flags else "규칙 위반 없음(새 발급 기록만)"))
        seen.add(k)
    sp.write_text(json.dumps({"domain": a.domain, "seen": sorted(seen)}, indent=1))
    print(f"상태 저장: {sp.name} ({len(seen)}장)")

if __name__ == "__main__":
    main()

"""매달린 CNAME·NS 점검기. 로컬 영역 파일과 로컬 자원 목록만 본다(실제 DNS 질의 없음).

    ../.venv/bin/python dangling.py lab.example.zone inventory.json

판정
- 위험: 외부 제공자로 가는데 자원 목록에 없다 → 그 이름을 남이 다시 만들면 우리 하위 도메인을 가져간다
- 확인: 목록에 없는 모르는 외부 → 누구 것인지 사람이 확인
- 정상: 영역 안 이름이거나, 목록에 있는 우리 자원
"""
import json
import sys

import dns.name
import dns.rdatatype
import dns.zone

def load(zone_file):
    with open(zone_file) as f:
        return dns.zone.from_file(f, origin="lab.example.", relativize=False)

def provider_of(host, providers):
    for suffix in providers:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None

def follow(zone, name, limit=8):
    """영역 안 CNAME 사슬을 따라가 마지막 대상(문자열)과 거친 길을 돌려준다."""
    path = [name]
    for _ in range(limit):
        node = zone.get_node(name)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.CNAME) if node else None
        if not rds:
            return name, path
        name = rds[0].target
        path.append(name)
        if not name.is_subdomain(zone.origin):
            return name, path
    return name, path + ["(고리 너무 김)"]

def main(zone_file, inv_file):
    zone = load(zone_file)
    inv = json.load(open(inv_file))
    owned = set(inv["owned_hostnames"])
    owned_zones = set(inv["owned_dns_zones"])
    rows = []
    for name, node in zone.nodes.items():
        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.CNAME):
            target, path = follow(zone, name)
            t = target.to_text().rstrip(".")
            via = " → ".join(p.to_text().rstrip(".") if hasattr(p, "to_text") else p for p in path)
            if target.is_subdomain(zone.origin):
                exists = zone.get_node(target) is not None
                rows.append(("정상" if exists else "위험", "CNAME", via, "영역 안" if exists else "영역 안 대상 없음"))
                continue
            prov = provider_of(t, inv["providers"])
            if prov and t in owned:
                rows.append(("정상", "CNAME", via, f"{prov} · 목록에 있음"))
            elif prov:
                rows.append(("위험", "CNAME", via, f"{prov} · 목록에 없음(지운 자원)"))
            else:
                rows.append(("확인", "CNAME", via, "모르는 외부 · 소유 확인 필요"))
        ns = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS)
        if ns and name != zone.origin:
            targets = sorted(r.target.to_text().rstrip(".") for r in ns)
            prov = {provider_of(t, inv["providers"]) for t in targets} - {None}
            sub = name.to_text().rstrip(".")
            if prov and sub not in owned_zones:
                rows.append(("위험", "NS", f"{sub} → {', '.join(targets)}", f"{','.join(prov)} · 위임 대상 영역이 목록에 없음"))
            else:
                rows.append(("정상", "NS", f"{sub} → {', '.join(targets)}", "목록에 있음"))
    order = {"위험": 0, "확인": 1, "정상": 2}
    rows.sort(key=lambda r: (order[r[0]], r[2]))
    print(f"영역: {zone.origin.to_text()}  이름 {len(zone.nodes)}개  (로컬 파일만 읽음, DNS 질의 0회)")
    for level, kind, via, why in rows:
        print(f"  [{level}] {kind:5} {via}\n         {why}")
    n = sum(1 for r in rows if r[0] == "위험")
    print(f"위험 {n}건, 확인 {sum(1 for r in rows if r[0] == '확인')}건, 정상 {sum(1 for r in rows if r[0] == '정상')}건")
    return 1 if n else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "lab.example.zone",
                  sys.argv[2] if len(sys.argv) > 2 else "inventory.json"))

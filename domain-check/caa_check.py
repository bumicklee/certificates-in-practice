"""CAA 레코드 파서·점검기 (RFC 8659, RFC 8657). 로컬 영역 파일만 읽는다.

    ../.venv/bin/python caa_check.py lab.example.zone shop.lab.example typo.lab.example ...

이름마다
1) 관련 RRset 찾기: 그 이름에 CAA가 없으면 부모로 올라간다(영역 꼭대기까지만. 실제로는 TLD 바로 아래까지 오른다).
   CNAME인 이름은 실제로는 별칭 대상 쪽 CAA가 먼저 보인다 → 로컬에서는 판정하지 않고 표시만 한다.
2) 레코드 문법 점검: 플래그, 태그, issue 값(발급자; 키=값), iodef URL, accounturi, validationmethods
3) 설계 점검: issue 있음, issuewild 결정, iodef 있음, accounturi 고정, 모르는 critical 태그
"""
import re
import sys

import dns.name
import dns.rdatatype
import dns.zone

KNOWN_TAGS = {"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}
KNOWN_CAS = {"letsencrypt.org", "pki.goog", "digicert.com", "sectigo.com", "amazon.com", "globalsign.com"}
ACME_METHODS = {"http-01", "dns-01", "tls-alpn-01"}   # IANA ACME Validation Methods 중 흔한 것. "ca-" 로 시작하면 CA 전용 라벨
LABEL = re.compile(r"^[A-Za-z0-9-]+$")

def relevant(zone, fqdn):
    name = dns.name.from_text(fqdn)
    cur = name
    while cur.is_subdomain(zone.origin):
        node = zone.get_node(cur)
        if node:
            if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.CNAME):
                return cur, None, "CNAME"
            rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.CAA)
            if rds:
                return cur, list(rds), None
        if cur == zone.origin:
            break
        cur = cur.parent()
    return cur, [], None

def parse_issue(value):
    parts = [p.strip() for p in value.split(";")]
    issuer, params = parts[0], {}
    for p in parts[1:]:
        if p:
            k, _, v = p.partition("=")
            params[k.strip()] = v.strip()
    return issuer, params

def check(rrs):
    probs, notes = [], []
    tags = [r.tag.decode() for r in rrs]
    for r in rrs:
        tag, val = r.tag.decode(), r.value.decode()
        if r.flags not in (0, 128):
            probs.append(f"플래그 {r.flags}: 0 또는 128만 쓴다")
        if tag not in KNOWN_TAGS:
            if r.flags & 128:
                probs.append(f"모르는 critical 태그 '{tag}' → 이 태그를 모르는 CA는 아무것도 발급하지 않는다")
            else:
                notes.append(f"모르는 태그 '{tag}'(critical 아님, 무시됨)")
            continue
        if tag in ("issue", "issuewild"):
            issuer, params = parse_issue(val)
            if issuer == "":
                notes.append(f"{tag} \";\" → 이 종류는 어떤 CA도 발급 금지")
                continue
            if issuer not in KNOWN_CAS:
                probs.append(f"{tag} 발급자 '{issuer}'가 아는 CA 식별자가 아니다(오타면 쓰려던 CA도 막힌다)")
            if "accounturi" in params and not params["accounturi"].startswith("https://"):
                probs.append("accounturi는 https:// 계정 URL이어야 한다")
            if "validationmethods" in params:
                for m in params["validationmethods"].split(","):
                    m = m.strip()
                    if not LABEL.match(m) or (m not in ACME_METHODS and not m.startswith("ca-")):
                        probs.append(f"validationmethods 라벨 '{m}'이 올바르지 않다(예: dns-01, http-01, tls-alpn-01)")
        if tag == "iodef" and not re.match(r"^(mailto:|https?://)", val):
            probs.append(f"iodef 값 '{val}'은 mailto: 또는 https:// URL이어야 한다")
    restricting = {"issue", "issuewild"} & set(tags)
    if not restricting:
        probs.append("issue/issuewild가 없다 → 이 이름에서는 CAA가 발급을 제한하지 않는다. 이 이름에 CAA가 있으니 부모의 엄격한 정책도 적용되지 않는다")
    else:
        if "issuewild" not in tags:
            notes.append("issuewild 없음 → 와일드카드도 issue 규칙을 따른다")
        if not any("accounturi=" in r.value.decode() for r in rrs if r.tag.decode() in ("issue", "issuewild")):
            notes.append("accounturi 없음 → 그 CA의 어느 계정으로든 발급 가능(RFC 8657로 좁힐 수 있다)")
    if "iodef" not in tags:
        notes.append("iodef 없음 → 위반 시도를 보고받을 곳이 없다(CA가 보내 줄 의무는 없다)")
    return probs, notes

def main(zone_file, names):
    with open(zone_file) as f:
        zone = dns.zone.from_file(f, origin="lab.example.", relativize=False)
    print(f"영역: {zone_file} (로컬 파일만 읽음, DNS 질의 0회)")
    for fqdn in names:
        at, rrs, special = relevant(zone, fqdn)
        print(f"\n== {fqdn}")
        if special == "CNAME":
            print(f"  {at.to_text()}는 CNAME → 실제 CAA 조회는 별칭 대상을 따라간다. 로컬 판정 생략")
            continue
        if not rrs:
            print("  관련 CAA 없음 → 어떤 CA든 발급 가능")
            continue
        print(f"  관련 RRset 위치: {at.to_text()}" + ("" if at.to_text().rstrip('.') == fqdn else "  (부모에서 찾음)"))
        for r in rrs:
            print(f"    {r.to_text()}")
        probs, notes = check(rrs)
        for p in probs:
            print(f"  [문제] {p}")
        for n in notes:
            print(f"  [참고] {n}")
        if not probs:
            print("  [통과]")

if __name__ == "__main__":
    zf = sys.argv[1] if len(sys.argv) > 1 else "lab.example.zone"
    names = sys.argv[2:] or ["lab.example", "shop.lab.example", "a.b.shop.lab.example", "typo.lab.example",
                             "badiodef.lab.example", "badvm.lab.example", "crit.lab.example", "open.lab.example",
                             "blog.lab.example"]
    main(zf, names)

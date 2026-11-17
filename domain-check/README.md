# domain-check: 매달린 CNAME 점검과 CAA 설계 (18편)

## 무엇
- `lab.example.zone` — 가짜 영역 파일. 외부 서비스로 가는 CNAME 여러 개, 지운 클라우드 DNS로 가는 NS 위임, CAA 좋은 예와 흔한 실수 예가 들어 있다. 이름은 모두 `.example`, 주소는 문서용 `192.0.2.0/24`.
- `inventory.json` — 우리가 **지금 실제로 가진** 외부 자원 목록(가짜). 실무에서는 클라우드 API·자산 목록에서 뽑는다.
- `dangling.py` — 영역 파일의 CNAME 사슬을 따라가 마지막 대상이 "외부 제공자인데 목록에 없음"이면 위험으로 표시한다. NS 위임도 본다.
- `caa_check.py` — CAA 파서·점검기. 이름마다 관련 RRset을 찾고(부모로 올라가기), 문법(RFC 8659)과 `accounturi`·`validationmethods`(RFC 8657), 설계 실수를 본다.

**실제 DNS 질의를 하지 않는다.** 남의 도메인을 훑는 도구가 아니다. 내 영역 파일(DNS 제공자에서 내보낸 것)과 내 자원 목록으로만 판단한다.

## 준비물
- `lab/.venv`(dnspython)

## 명령 (`lab/domain-check/`에서)
```bash
../.venv/bin/python dangling.py lab.example.zone inventory.json   # 위험이 있으면 종료 코드 1
../.venv/bin/python caa_check.py lab.example.zone                  # 기본 이름 목록
../.venv/bin/python caa_check.py lab.example.zone shop.lab.example open.lab.example
```
결과 파일(직접 돌리면 생김): `../results/13-dangling.txt`, `../results/13-caa-check.txt`

## 내 도메인에 쓰려면
1. DNS 제공자에서 영역 파일을 내보낸다(BIND 형식).
2. `inventory.json`의 `providers`에 쓰는 클라우드·SaaS 접미사를, `owned_hostnames`에 지금 가진 자원 이름을 넣는다.
3. 위 명령을 CI에서 매일 돌리고, 위험이 나오면 레코드를 지우거나 자원을 다시 확보한다.

## 정리
만드는 파일·서버 없음.

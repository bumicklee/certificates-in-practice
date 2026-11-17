# ct-watch: 공개 CT 검색과 새 발급 알림 (20편)

## 무엇
- `ct_search.py` — crt.sh JSON(`?q=<도메인>&output=json&exclude=expired`)을 **읽기만** 한다. 결과는 `../results/15-crtsh-<도메인>.json`에 캐시하고, 캐시가 있으면 요청하지 않는다. `--refresh`일 때만 1회 요청(실패하면 15초 뒤 1회만 다시).
- `ct_watch.py` — 캐시를 로컬 상태 파일(`state/<도메인>.json`)과 비교해 처음 보는 인증서만 알린다. 같은 발급자·일련번호는 하나로 묶는다(사전 인증서와 최종 인증서가 둘 다 로그에 오른다).
  - 알림 규칙: 처음 본 인증서 / 기대한 발급자 아님(`--expect-issuer`) / 와일드카드 / 모르는 이름(`--expect-name`)
  - `--seed-before YYYY-MM-DD`: 상태 파일이 없을 때 그 날짜 이전 항목을 "이미 본 것"으로 기준선을 만든다(첫 실행 데모용).

## 준비물
- `lab/.venv`(httpx), 인터넷(crt.sh 읽기)

## 명령 (`lab/ct-watch/`에서)
```bash
../.venv/bin/python ct_search.py example.com            # 캐시가 없으면 1회 요청
../.venv/bin/python ct_watch.py example.com --expect-issuer Sectigo --seed-before 2026-09-01
../.venv/bin/python ct_watch.py example.com --expect-issuer Sectigo   # 다시 돌리면 0건
```
결과 파일(직접 돌리면 생김): `../results/15-crtsh-example.com.json`(crt.sh 응답 그대로), `../results/15-ct-search.txt`, `../results/15-ct-watch.txt`

`--expect-issuer Sectigo`는 실습용 **가정**이다. example.com 운영자가 실제로 어떤 CA를 쓰기로 했는지는 모른다. 내 도메인에는 CAA에 적은 CA와 같게 둔다(18편).

## 내 도메인에 쓰려면
- 하루 1~2회 cron/CI로 `ct_search.py <내 도메인> --refresh` → `ct_watch.py <내 도메인> --expect-issuer <우리 CA>`.
- crt.sh는 무료 공익 서비스라 느리거나 503을 낼 때가 있다. 자주 부르지 말고, 실패하면 다음 회차에 다시 본다. 운영에서는 CA·CDN·보안 업체의 CT 알림 서비스를 함께 쓰는 것이 낫다.

## 정리
```bash
rm -rf state
```

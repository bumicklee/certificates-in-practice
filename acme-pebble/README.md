# lab/acme-pebble — 로컬 ACME 발급·갱신·ARI (Pebble)

수업 4-1·4-2·4-3·4-4 실습 폴더입니다. 진짜 도메인 없이 Let's Encrypt와 같은 프로토콜(RFC 8555)로 발급·갱신하고, ARI(RFC 9773) 응답을 봅니다.

## 구성

| 컨테이너 | 이미지(고정) | 역할 | 호스트 포트(127.0.0.1) |
|---|---|---|---|
| `pki-lab-acme-pebble` | `ghcr.io/letsencrypt/pebble:2.10.1` | 시험용 ACME CA | 18420(ACME), 18421(관리 API) |
| `pki-lab-acme-dns` | `ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1` | 시험용 DNS. 모든 A 질의에 web IP를 답하고, TXT는 API로 넣는다 | 18422(관리 API), 18424/udp(DNS) |
| `pki-lab-acme-web` | `nginx:1.30.6-alpine` + `goacme/lego:v5.5.2` 바이너리 (`Dockerfile.web`) | 인증서를 받을 서버. nginx가 `/.well-known/acme-challenge/`를 서빙하고 lego가 발급·갱신 | 18423(HTTPS) |

모두 도커 네트워크 `pki-lab-acme`(10.30.0.0/24) 안에서 이야기합니다. Pebble 설정은 `config/pebble-config.json`(프로필 `default` 90일, `shortlived` 160시간).

## 준비물

Docker, 호스트의 `curl`·`openssl`·`dig`, `../.venv/bin/python`(cryptography, ARI certID 계산용).

## 명령

```bash
cd lab/acme-pebble
./up.sh              # 세 컨테이너 띄우기
./issue-http01.sh    # 수업 4-1·4-2: HTTP-01로 shop.lab.example 발급 → nginx TLS        → ../results/06-http01.txt
./issue-dns01.sh     # 수업 4-1·4-2: *.lab.example — HTTP-01 거절, DNS-01(exec 훅) 발급  → ../results/06-dns01.txt
./keys.sh            # 수업 4-1·4-2: 계정 키와 인증서 키가 다르다(공개키 지문만 출력)    → ../results/06-keys.txt
./renew.sh           # 수업 4-3·4-4: ARI 창 보기, 평소 실행은 건너뜀, 강제 갱신+reload 훅, 무중단 확인 → ../results/07-renew.txt
./ari-revoke.sh      # 수업 4-3·4-4: 폐기하면 ARI 창이 "지금"으로 당겨지고 lego가 바로 갱신 → ../results/07-ari-revoke.txt
./down.sh            # 정리
```

`issue-http01.sh`를 먼저 돌려야 나머지가 동작합니다(nginx TLS 설정과 발급 루트 파일을 만든다).

## 파일

- `hooks/dns-challtestsrv.sh` — lego `exec` DNS 공급자 훅. 실서비스라면 이 자리에 DNS 공급자 API 호출이 들어간다(그 토큰 권한을 좁혀야 한다).
- `hooks/deploy-reload.sh` — 새 인증서가 나왔을 때만 불리는 훅. `nginx -t` 후 `nginx -s reload`.
- `ari_certid.py` — 인증서에서 ARI certID(`base64url(AKI).base64url(serial)`)를 만든다.
- `out/` — Pebble API용 시험 루트(`pebble-api-minica.pem`), 발급 루트(`pebble-issuing-root.pem`, Pebble을 다시 띄우면 바뀐다), 꺼내 본 인증서.

## 주의

- Pebble은 시험용입니다. 띄울 때마다 루트가 바뀌고, 데이터는 메모리에만 있습니다.
- 이 실습의 Pebble 디렉터리에서 ARI 주소는 `.../draft-ietf-acme-ari-03/renewalInfo`로 나옵니다. 주소는 반드시 디렉터리의 `renewalInfo` 값을 읽어 씁니다.
- 프로필을 지정하지 않았을 때 160시간짜리가 나온 적이 있어서, 스크립트는 `--profile`을 늘 명시합니다.

## 정리

```bash
./down.sh
docker ps --filter name=pki-lab-acme   # 비어 있어야 한다
```

# lab/mtls — mTLS 실패 네 가지, 헤더 위조, 무중단 CA 교체, PostgreSQL sslmode

수업 6-1·6-2·6-3 실습 폴더입니다. 공용 사설 CA `../private-ca/out/`은 **읽기만** 합니다. 추가 인증서는 `gen_certs.sh`가 `out/`에 만듭니다.

## 구성

| 컨테이너 | 이미지(고정) | 역할 | 호스트 포트(127.0.0.1) |
|---|---|---|---|
| `pki-lab-mtls-nginx` | `nginx:1.30.6-alpine` | 8443: mTLS 종료(`ssl_verify_client on`) → 안전 백엔드 / 8444: 일부러 잘못 만든 프록시 → 취약 백엔드 / 8445: CA 교체 실험 | 18440 / 18441 / 18443 |
| `pki-lab-mtls-backend-vuln` | `backend/Dockerfile`(python:3.14.10-slim-trixie + cryptography 50.0.2) | `X-Client-Cert`를 누가 보냈든 믿는다 | 18442 (일부러 열어 둠) |
| `pki-lab-mtls-backend-safe` | 같은 이미지, `TRUSTED_PROXY=10.31.0.10` | 프록시 IP에서 온 요청만 받는다. 호스트 포트 없음 | 없음 |
| `pki-lab-mtls-pg` | `postgres:17.11-alpine` | `pg.sh`가 잠깐 띄웠다 지운다 | 18445 |

백엔드(`backend/app.py`)는 헤더의 인증서에서 SAN URI(SPIFFE ID)를 읽고, 경로별 허용 목록(`/orders` ← `spiffe://lab.example/orders`)으로 인가합니다.

## 인증서 (`./gen_certs.sh` → out/)

| 폴더 | 발급자 | SAN URI | 쓰임 |
|---|---|---|---|
| `ok` | 사내 중간 CA(private-ca의 client.crt) | `spiffe://lab.example/orders` | 정상 |
| `payments` | 사내 중간 CA | `spiffe://lab.example/payments` | 인증 통과, 인가 실패 |
| `expired` | 사내 중간 CA | orders | 2026-10-01에 만료 |
| `otherca` | 다른 루트 `Other Lab Root` | orders | 신뢰하지 않는 CA |
| `ca2` | 교체용 새 루트 `Lab Example Root R2` | orders | 수업 6-2·6-3 무중단 교체 |
| `pg` | 자체 서명 CN=wrong.example | | 수업 6-2·6-3 PostgreSQL |

## 준비물

Docker, `../.venv/bin/python`(httpx), Go 1.25+, `curl`, `openssl`, `psql`·`pg_isready`.
`../private-ca/out/`이 없으면 먼저 `../private-ca/make_chain.sh`.

## 명령

```bash
cd lab/mtls
./gen_certs.sh
./up.sh
../.venv/bin/python clients/client.py         # 수업 6-1: 정상 + 실패 네 가지 + 서버 이름 불일치 → ../results/09-python-client.txt
(cd clients/go && go run .)                   # 수업 6-1: 같은 다섯 경우를 Go로                    → ../results/09-go-client.txt
docker logs pki-lab-mtls-nginx | grep verify=  # nginx가 본 검증 결과                           → ../results/09-nginx-access.txt
./spoof.sh                                    # 수업 6-2·6-3: 헤더 위조가 통하는 곳/막히는 곳          → ../results/10-header-spoof.txt
./rotate.sh                                   # 수업 6-2·6-3: R1 → R1+R2 → R2, reload 중 끊김 세기     → ../results/10-rotation.txt
./pg.sh                                       # 수업 6-2·6-3: psql require vs verify-ca vs verify-full → ../results/10-postgres-sslmode.txt
./down.sh
```

핸드셰이크 메시지 보기(수업 6-1, `../results/09-handshake.txt`):

```bash
printf 'GET /orders HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
  openssl s_client -connect 127.0.0.1:18440 -servername localhost -CAfile ../private-ca/out/root.crt \
  -cert out/ok/chain.pem -key out/ok/client.key -msg -ign_eof 2>&1 | grep 'TLS 1.3, Handshake'
```

## 주의

- 취약 프록시(18441)와 취약 백엔드(18442)는 **일부러 잘못 만든 것**입니다. 127.0.0.1에만 열고, 실습이 끝나면 `./down.sh`로 지웁니다.
- 안전 백엔드의 "프록시 IP만" 검사는 실습용 최소 장치입니다. 실무에서는 프록시↔백엔드 구간도 mTLS로 묶거나 네트워크 정책으로 막습니다(수업 6-2·6-3).
- PostgreSQL 비밀번호 `fake-lab-password-only`는 실습용입니다.

## 정리

```bash
./down.sh
docker ps --filter name=pki-lab-mtls   # 비어 있어야 한다
```

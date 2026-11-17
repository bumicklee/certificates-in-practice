# nginx-hardening: 127.0.0.1 전용 TLS 하드닝 nginx (16편, 10·32편)

## 무엇
- `conf/default.conf` — Mozilla SSL Configuration Generator "intermediate"(guidelines 6.0)를 바탕으로 한 설정
  - TLS 1.2/1.3만, TLS 1.2는 ECDHE + AEAD 스위트만, 키 교환 그룹 `X25519MLKEM768:X25519:prime256v1:secp384r1`
  - HSTS `max-age=63072000; includeSubDomains; preload` (`always`로 오류 응답에도 붙인다)
  - HTTP(80) → 같은 호스트 HTTPS로 301
- `run.sh start|stop|status` — 컨테이너 `pki-lab-nginx-hardening`(이미지 `nginx:1.30.6-alpine`, 고정)
  - HTTPS: `https://localhost:18450` (컨테이너 443)
  - HTTP:  `http://localhost:18451` (컨테이너 80) → `https://localhost:18450`으로 이동
  - 인증서: `../private-ca/out/chain.pem`, `leaf.key`를 **읽기 전용**으로 붙인다(SAN: shop.lab.example, localhost, 127.0.0.1)
- `check_hsts.py` — HSTS 헤더와 HTTP 이동을 보고 hstspreload.org 제출 조건 중 로컬에서 볼 수 있는 것을 점검한다.

## 준비물
- Docker, `../private-ca/out/`(없으면 `../private-ca/make_chain.sh`)
- `lab/.venv`(httpx)

## 명령 (`lab/nginx-hardening/`에서)
```bash
./run.sh start
curl -sI --cacert ../private-ca/out/ca-bundle.pem https://localhost:18450/
curl -sI http://localhost:18451/
../.venv/bin/python check_hsts.py
../.venv/bin/python check_hsts.py --header "max-age=300"     # 접속 없이 헤더 문자열만
./run.sh stop
```

### 다른 편에서 쓸 때 (10·32편 testssl.sh)
`./run.sh start` 후 `127.0.0.1:18450`을 점검 대상으로 쓰고, 끝나면 `./run.sh stop`. 컨테이너에서 호스트로 붙을 때는
`host.docker.internal:18450`을 쓰거나, testssl 컨테이너를 `--network container:pki-lab-nginx-hardening`으로 붙여 `localhost:443`을 본다.
신뢰 저장소는 `../private-ca/out/ca-bundle.pem`이다.

결과 파일(직접 돌리면 생김): `../results/12-curl-headers.txt`, `../results/12-tls-versions.txt`, `../results/12-preload-check.txt`

## 정리
```bash
./run.sh stop
docker ps --filter name=pki-lab-     # 비어 있어야 한다
```

## 주의
- `includeSubDomains`·`preload`는 실습용으로 켰다. 실서비스에서는 **모든 하위 도메인이 HTTPS**인지 확인한 뒤에만 켠다. preload 목록에서 빠지는 데는 몇 달이 걸린다.
- OCSP 스테이플링은 껐다. 사설 CA에 OCSP 응답기가 없다.

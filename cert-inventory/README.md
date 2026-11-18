# cert-inventory (수업 4-4·10-2)

"내 인증서 만료 목록"을 한 표로 모은다. TLS 엔드포인트, PEM 폴더, kubeadm 모양 pki 폴더(+kubeconfig), 쿠버네티스 TLS 비밀값 YAML.

- `gen_fixtures.py` 수명이 제각각인 가짜 인증서를 `fixtures/`에 만든다(SAML IdP 서명, APNs 흉내, 코드 서명, 만료 루트가 섞인 기기 루트 묶음, kubeadm 클러스터 335일차)
- `tls_servers.py` 127.0.0.1:18494(90일)·18495(6일)·18496(398일)에 TLS 서버 3개(한 프로세스)
- `inventory.py` 남은 날짜 순 표, `--warn` 일 안쪽 경고, `--prom`으로 Prometheus 텍스트 파일

## 실행
```bash
./run.sh    # 결과: ../results/22-cert-inventory.txt. 18497은 일부러 비운 포트(접속 실패 줄)
../.venv/bin/python inventory.py --endpoint 내호스트:443 --pem-dir /etc/ssl/내폴더 --warn 30   # 내 환경에
```

## testssl.sh (수업 4-4·10-2)
`../nginx-hardening/run.sh start` 뒤 `../nginx-hardening/README.md`의 `docker run ... drwetter/testssl.sh:3.2@sha256:69ceb759...` 명령, 끝나면 `../nginx-hardening/run.sh stop`. 결과: `../results/22-testssl.txt`

## 정리
`run.sh`가 서버를 끈다. 재료까지 지우려면 `rm -rf fixtures`.

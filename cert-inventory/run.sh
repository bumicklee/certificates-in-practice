#!/usr/bin/env bash
# 10·32편 실습: 가짜 인증서 만들기 → TLS 서버 3개 → 만료 목록 → 서버 끄기
set -uo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
$PY gen_fixtures.py
$PY tls_servers.py & SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1
$PY inventory.py \
  --endpoint 127.0.0.1:18494 --endpoint 127.0.0.1:18495 --endpoint 127.0.0.1:18496 --endpoint 127.0.0.1:18497 \
  --pem-dir fixtures/pem --kube-pki fixtures/kube-pki --k8s-secrets fixtures/k8s-secrets \
  --warn 30 --prom fixtures/cert_expiry.prom
echo "exit=$?"
echo; echo "Prometheus 텍스트 파일(앞 5줄):"; head -5 fixtures/cert_expiry.prom

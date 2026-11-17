#!/usr/bin/env bash
# nginx(mTLS 종료) + 백엔드 두 개(취약/안전)를 띄운다. 호스트에는 127.0.0.1만 연다.
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
[[ -f out/ok/chain.pem ]] || ./gen_certs.sh
mkdir -p out/rot; [[ -f out/rot/trust.pem ]] || cp $PCA/root.crt out/rot/trust.pem
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.31.0.0/24 $NET >/dev/null
docker build -q -t $BACKEND_IMG backend >/dev/null
# 취약 백엔드: 헤더를 누가 보냈든 믿는다. 게다가 호스트 포트로도 열려 있다(127.0.0.1:18442)
docker run -d --name pki-lab-mtls-backend-vuln --network $NET --ip 10.31.0.20 \
  -p 127.0.0.1:18442:8080 $BACKEND_IMG >/dev/null
# 안전 백엔드: 포트를 밖에 열지 않고, 프록시 IP에서 온 요청만 받는다
docker run -d --name pki-lab-mtls-backend-safe --network $NET --ip 10.31.0.21 \
  -e TRUSTED_PROXY=10.31.0.10 $BACKEND_IMG >/dev/null
docker run -d --name pki-lab-mtls-nginx --network $NET --ip 10.31.0.10 \
  -v "$PWD/nginx/mtls.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PCA/chain.pem:/pca/chain.pem:ro" -v "$PCA/leaf.key:/pca/leaf.key:ro" -v "$PCA/root.crt:/pca/root.crt:ro" \
  -v "$PWD/out/rot:/rot:ro" \
  -p 127.0.0.1:18440:8443 -p 127.0.0.1:18441:8444 -p 127.0.0.1:18443:8445 $NGINX_IMG >/dev/null
sleep 2
docker ps --filter name=pki-lab-mtls --format 'table {{.Names}}\t{{.Ports}}'

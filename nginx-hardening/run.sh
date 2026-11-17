#!/usr/bin/env bash
# 하드닝한 nginx 를 127.0.0.1 에 띄우고 끈다.
#   ./run.sh start    # https://localhost:18450 , http://localhost:18451
#   ./run.sh stop
#   ./run.sh status
# 인증서는 ../private-ca/out 의 chain.pem·leaf.key 를 읽기 전용으로 붙인다(없으면 ../private-ca/make_chain.sh 먼저).
set -euo pipefail
cd "$(dirname "$0")"
NAME=pki-lab-nginx-hardening
IMAGE=nginx:1.30.6-alpine
CA=$(cd ../private-ca/out && pwd)
case "${1:-}" in
  start)
    [[ -f "$CA/chain.pem" ]] || { echo "먼저 ../private-ca/make_chain.sh 를 실행하세요"; exit 1; }
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
      -p 127.0.0.1:18450:443 -p 127.0.0.1:18451:80 \
      -v "$(pwd)/conf/default.conf:/etc/nginx/conf.d/default.conf:ro" \
      -v "$CA/chain.pem:/etc/nginx/certs/chain.pem:ro" \
      -v "$CA/leaf.key:/etc/nginx/certs/leaf.key:ro" \
      "$IMAGE" >/dev/null
    for _ in $(seq 1 20); do
      curl -s -o /dev/null --cacert "$CA/ca-bundle.pem" https://localhost:18450/ && { echo "시작: $NAME ($IMAGE) https://localhost:18450 http://localhost:18451"; exit 0; }
      sleep 0.5
    done
    echo "응답 없음"; docker logs "$NAME" | tail -20; exit 1 ;;
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "정리: $NAME" || echo "떠 있지 않음: $NAME" ;;
  status)
    docker ps --filter "name=$NAME" --format '{{.Names}}  {{.Image}}  {{.Ports}}' ;;
  *) echo "사용법: $0 start|stop|status"; exit 2 ;;
esac

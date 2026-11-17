#!/usr/bin/env bash
# 7·8편: HTTP-01로 shop.lab.example 발급 → nginx에서 TLS로 열고 확인
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
echo "== 1) ACME 디렉터리(호스트에서 보기)"
curl -s --cacert out/pebble-api-minica.pem https://localhost:18420/dir
echo; echo "== 2) lego run --http (webroot: nginx가 /.well-known/acme-challenge/ 를 서빙)"
lego_in_web run --accept-tos --email admin@lab.example \
  --server $DIR --path /data/lego \
  --domains shop.lab.example --profile default \
  --http --http.webroot /var/www/acme 2>&1
echo; echo "== 3) Pebble이 우리 nginx에 와서 읽어 간 경로(nginx 접근 로그)"
docker logs pki-lab-acme-web 2>/dev/null | grep acme-challenge || true
echo; echo "== 4) 받은 파일"
docker exec pki-lab-acme-web sh -c 'ls -1 /data/lego/certificates/'
echo; echo "== 5) 발급 루트를 Pebble 관리 API에서 받아 저장(Pebble은 띄울 때마다 새 루트를 만든다)"
curl -s --cacert out/pebble-api-minica.pem https://localhost:18421/roots/0 > out/pebble-issuing-root.pem
openssl x509 -in out/pebble-issuing-root.pem -noout -subject
echo; echo "== 6) nginx에 TLS 서버를 켜고 reload"
docker cp -q config/nginx-tls.conf pki-lab-acme-web:/etc/nginx/conf.d/tls.conf
docker exec pki-lab-acme-web nginx -s reload 2>&1; sleep 1
curl -s --resolve shop.lab.example:18423:127.0.0.1 --cacert out/pebble-issuing-root.pem https://shop.lab.example:18423/
echo | openssl s_client -connect 127.0.0.1:18423 -servername shop.lab.example 2>/dev/null \
  | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName

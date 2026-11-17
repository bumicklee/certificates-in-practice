#!/usr/bin/env bash
# Pebble(시험용 ACME CA) + challtestsrv(시험용 DNS) + web(nginx+lego)를 띄운다. 모두 127.0.0.1에만 연다.
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
mkdir -p out
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet $SUBNET $NET >/dev/null
docker build -q -f Dockerfile.web -t $WEB_IMG . >/dev/null
# 시험용 DNS: 모든 A 질의에 web 컨테이너 IP를 돌려준다
docker run -d --name pki-lab-acme-dns --network $NET --ip 10.30.0.3 --network-alias challtestsrv \
  -p 127.0.0.1:18422:8055 -p 127.0.0.1:18424:8053/udp \
  $CHALL_IMG -defaultIPv4 $WEB_IP -defaultIPv6 "" -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
# Pebble: 검증할 때 위 DNS만 본다. 일부러 넣는 지연·nonce 거절은 끈다
docker run -d --name pki-lab-acme-pebble --network $NET --ip 10.30.0.2 --network-alias pebble \
  -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 -e PEBBLE_AUTHZREUSE=0 \
  -v "$PWD/config/pebble-config.json:/test/config/pebble-config.json:ro" \
  -p 127.0.0.1:18420:14000 -p 127.0.0.1:18421:15000 \
  $PEBBLE_IMG -config /test/config/pebble-config.json -dnsserver 10.30.0.3:8053 >/dev/null
# Pebble의 API용 TLS 인증서를 믿을 수 있게 시험용 루트를 꺼내 둔다(발급 루트와는 다르다)
cid=$(docker create $PEBBLE_IMG); docker cp -q $cid:/test/certs/pebble.minica.pem out/pebble-api-minica.pem; docker rm $cid >/dev/null
docker run -d --name pki-lab-acme-web --network $NET --ip $WEB_IP \
  -v "$PWD/config/nginx-acme.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PWD/hooks:/hooks:ro" -v "$PWD/out/pebble-api-minica.pem:/etc/pebble/minica.pem:ro" \
  -p 127.0.0.1:18423:443 $WEB_IMG >/dev/null
sleep 2
docker ps --filter name=pki-lab-acme --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'

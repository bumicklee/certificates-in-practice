#!/usr/bin/env bash
# 수업 4-1·4-2: 와일드카드는 DNS-01만 된다. HTTP-01로 시도 → 거절, DNS-01로 시도 → 발급
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
docker exec pki-lab-acme-web sh -c "rm -f /data/lego/certificates/_.lab.example.*"  # 다시 돌릴 수 있게
echo "== 1) *.lab.example 을 HTTP-01로 시도"
lego_in_web run --accept-tos --email admin@lab.example --server $DIR --path /data/lego \
  --domains '*.lab.example' --profile default --http --http.webroot /var/www/acme 2>&1 | tail -4
echo; echo "== 2) 같은 와일드카드를 DNS-01로 (exec 훅이 시험용 DNS API에 TXT를 쓴다)"
( sleep 7; echo "-- 발급 도중 호스트에서 본 TXT 레코드 (dig @127.0.0.1 -p 18424)";
  dig +short @127.0.0.1 -p 18424 TXT _acme-challenge.lab.example ) &
docker exec -e LEGO_CA_CERTIFICATES=/etc/pebble/minica.pem -e EXEC_PATH=/hooks/dns-challtestsrv.sh pki-lab-acme-web \
  lego run --accept-tos --email admin@lab.example --server $DIR --path /data/lego \
  --domains '*.lab.example' --profile default \
  --dns exec --dns.propagation.wait 5s 2>&1
wait
echo; echo "-- 발급 뒤 TXT 레코드(cleanup 훅이 지웠는지)"
dig +short @127.0.0.1 -p 18424 TXT _acme-challenge.lab.example; echo "(빈 줄이면 지워짐)"
echo; echo "== 3) 받은 와일드카드 인증서"
docker exec pki-lab-acme-web cat /data/lego/certificates/_.lab.example.crt | openssl x509 -noout -issuer -dates -ext subjectAltName

#!/usr/bin/env bash
# 수업 4-3·4-4: 갱신 판단(ARI) → 강제 갱신 + deploy hook(reload) → 끊김 없는지 확인
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
PY=../.venv/bin/python
CA=out/pebble-api-minica.pem
serial_now() { echo | openssl s_client -connect 127.0.0.1:18423 -servername shop.lab.example 2>/dev/null | openssl x509 -noout -serial; }

echo "== 1) 디렉터리의 renewalInfo 주소"
RI=$(curl -s --cacert $CA https://localhost:18420/dir | $PY -c 'import sys,json;print(json.load(sys.stdin)["renewalInfo"])'); echo "$RI"

echo; echo "== 2) 지금 인증서의 certID와 ARI 응답"
docker exec pki-lab-acme-web cat /data/lego/certificates/shop.lab.example.crt > out/shop.crt
openssl x509 -in out/shop.crt -noout -serial -dates
ID=$($PY ari_certid.py out/shop.crt); echo "certID=$ID"
curl -s -i --cacert $CA "$RI/$ID" | grep -iE '^(HTTP|retry-after)|suggestedWindow|start|end|explanation' 
echo; echo "== 3) 그냥 다시 돌리면(cron이 매일 부르는 모양): 갱신할 때가 아니면 아무 일도 안 한다"
lego_in_web run --email admin@lab.example --server $DIR --path /data/lego \
  --domains shop.lab.example --profile default --http --http.webroot /var/www/acme \
  --no-random-sleep --deploy-hook /hooks/deploy-reload.sh 2>&1

echo; echo "== 4) 강제 갱신(--renew-force) + deploy hook. 그동안 0.05초마다 요청을 보내 끊김을 센다"
echo "갱신 전 $(serial_now)"
( ok=0; bad=0; for i in $(seq 1 120); do
    if curl -s -o /dev/null --max-time 2 --resolve shop.lab.example:18423:127.0.0.1 --cacert out/pebble-issuing-root.pem https://shop.lab.example:18423/; then ok=$((ok+1)); else bad=$((bad+1)); fi
    sleep 0.05; done; echo "-- 갱신 중 요청 결과: 성공 $ok / 실패 $bad" ) &
lego_in_web run --email admin@lab.example --server $DIR --path /data/lego \
  --domains shop.lab.example --profile default --http --http.webroot /var/www/acme \
  --renew-force --no-random-sleep --deploy-hook /hooks/deploy-reload.sh 2>&1
wait
echo "갱신 후 $(serial_now)"

echo; echo "== 5) 비교: 160시간짜리(shortlived 프로필)의 ARI 창"
docker exec pki-lab-acme-web sh -c "rm -f /data/lego/certificates/short.lab.example.*"
lego_in_web run --email admin@lab.example --server $DIR --path /data/lego \
  --domains short.lab.example --profile shortlived --http --http.webroot /var/www/acme 2>&1 | grep -E 'validated|Server responded'
docker exec pki-lab-acme-web cat /data/lego/certificates/short.lab.example.crt > out/short.crt
openssl x509 -in out/short.crt -noout -dates
curl -s --cacert $CA "$RI/$($PY ari_certid.py out/short.crt)"; echo

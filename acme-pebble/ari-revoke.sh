#!/usr/bin/env bash
# 수업 4-3·4-4: CA가 "지금 바꿔라"라고 알리는 경우. 폐기된 인증서의 ARI 창이 어떻게 바뀌는지 본다.
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
PY=../.venv/bin/python; CA=out/pebble-api-minica.pem
RI=$(curl -s --cacert $CA https://localhost:18420/dir | $PY -c 'import sys,json;print(json.load(sys.stdin)["renewalInfo"])')
docker exec pki-lab-acme-web cat /data/lego/certificates/short.lab.example.crt > out/short.crt
ID=$($PY ari_certid.py out/short.crt)
echo "== 폐기 전 ARI ($(date -u +%FT%TZ))"; curl -s --cacert $CA "$RI/$ID"; echo
echo "== 폐기 (reason 1 = keyCompromise 가정)"
lego_in_web certificates revoke --email admin@lab.example --server $DIR --path /data/lego --cert.name short.lab.example --reason 1 --keep 2>&1
echo "== 폐기 후 ARI"; curl -s --cacert $CA "$RI/$ID"; echo
echo "== 같은 인증서로 lego run (ARI를 보고 갱신하는지)"
lego_in_web run --email admin@lab.example --server $DIR --path /data/lego \
  --domains short.lab.example --profile shortlived --http --http.webroot /var/www/acme --no-random-sleep 2>&1 | grep -vE 'Writing file'

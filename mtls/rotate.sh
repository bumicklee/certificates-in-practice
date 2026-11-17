#!/usr/bin/env bash
# 14·15편 ④: 클라이언트 CA 무중단 교체. R1만 → R1+R2(겹치는 기간) → R2만. 바꿀 때마다 nginx -s reload.
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
ROOT=$PCA/root.crt
req() { curl -s -o /dev/null -w '%{http_code}' --cacert $ROOT --cert out/$1/chain.pem --key out/$1/client.key https://localhost:18443/; }
both() { echo "  R1 클라이언트(ok): $(req ok)   R2 클라이언트(ca2): $(req ca2)"; }
trust() { cat "$@" > out/rot/trust.pem; docker exec pki-lab-mtls-nginx nginx -s reload 2>&1 | grep -v 'signal process'; sleep 1; }
echo "== 0) 믿는 루트: R1만"; trust $PCA/root.crt; both
echo "== 1) 겹치는 기간: R1+R2. reload 하는 동안 R1 클라이언트로 0.05초마다 요청"
( ok=0; bad=0; for i in $(seq 1 80); do [[ $(req ok) == 200 ]] && ok=$((ok+1)) || bad=$((bad+1)); sleep 0.05; done
  echo "  reload 중 R1 요청: 성공 $ok / 실패 $bad" ) &
sleep 1; trust $PCA/root.crt out/ca2/root.crt; wait; both
echo "  (이 기간에 클라이언트들이 R2 인증서로 하나씩 갈아탄다)"
echo "== 2) 교체 끝: R2만"; trust out/ca2/root.crt; both
echo "== 3) 되돌려 둔다(R1만)"; trust $PCA/root.crt; both

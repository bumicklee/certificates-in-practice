#!/usr/bin/env bash
# 127.0.0.1:18400에 TLS 1.3 시험 서버를 띄운다 (lab/private-ca/out 사슬 사용).
#   ./server.sh start   # 뒤에서 띄우고 PID를 server.pid에 적는다
#   ./server.sh stop
set -euo pipefail
cd "$(dirname "$0")"
CA=../private-ca/out
PORT="${PORT:-18400}"
case "${1:-start}" in
  start)
    [[ -f "$CA/leaf.crt" ]] || { echo "먼저 ../private-ca/make_chain.sh 를 돌리세요"; exit 1; }
    openssl s_server -accept "127.0.0.1:$PORT" -naccept 50 \
      -cert "$CA/leaf.crt" -key "$CA/leaf.key" -cert_chain "$CA/inter.crt" \
      -groups X25519MLKEM768:x25519:secp256r1 -www -quiet >server.log 2>&1 &
    echo $! > server.pid; sleep 1; echo "s_server pid $(cat server.pid) on 127.0.0.1:$PORT" ;;
  stop)
    [[ -f server.pid ]] && kill "$(cat server.pid)" 2>/dev/null || true; rm -f server.pid; echo stopped ;;
esac

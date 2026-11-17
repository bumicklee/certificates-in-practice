#!/usr/bin/env bash
# 그룹(키 교환 방식)별로 ClientHello·ServerHello key_share 크기와 협상 결과를 비교한다.
set -euo pipefail
cd "$(dirname "$0")"
CA=../private-ca/out; PORT="${PORT:-18400}"
for g in x25519 secp256r1 X25519MLKEM768; do
  out=$(openssl s_client -connect 127.0.0.1:$PORT -servername shop.lab.example \
        -CAfile $CA/ca-bundle.pem -groups $g -trace -brief </dev/null 2>&1)
  sizes=$(echo "$out" | grep -o 'key_exchange:  (len=[0-9]*)' | grep -o '[0-9]*' | paste -sd/ -)
  neg=$(echo "$out" | grep -E 'Negotiated TLS1.3 group|Peer Temp Key' | sed 's/.*: //; s/, [0-9]* bits//; s/, /-/' || true)
  ver=$(echo "$out" | grep -E '^Verification' | sed 's/.*: //')
  printf "%-16s key_share(클라이언트/서버 바이트)=%-10s 협상=%-16s 검증=%s\n" "$g" "$sizes" "$neg" "$ver"
done

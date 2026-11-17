#!/usr/bin/env bash
# 같은 서버, 같은 인증서로 세 번 접속해 서버 key_share 앞 32자리를 비교한다.
# 매번 다르면 연결마다 새 임시 키(ephemeral)를 쓴다는 뜻이다 = PFS.
set -euo pipefail
cd "$(dirname "$0")"
CA=../private-ca/out; PORT="${PORT:-18400}"
echo "서버 인증서 공개키 지문(SHA-256, 세 번 모두 같아야 함):"
openssl x509 -in $CA/leaf.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | sed 's/.*= /  /'
for i in 1 2 3; do
  ks=$(openssl s_client -connect 127.0.0.1:$PORT -servername shop.lab.example -CAfile $CA/ca-bundle.pem \
        -groups x25519 -trace </dev/null 2>&1 | awk '/ServerHello/{s=1} s&&/key_exchange:/{print $NF; exit}')
  echo "접속 $i  서버 X25519 임시 공개키: ${ks:0:32}..."
done

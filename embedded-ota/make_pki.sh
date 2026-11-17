#!/usr/bin/env bash
# 24편 실습용 키와 사슬을 out/ 에 만든다. 가짜 이름만 쓴다.
#   out/ota/ota_sign.key, ota_sign.pub   OTA 이미지 서명 키(ECDSA P-256). 실제로는 HSM·AWS Signer 안에 둔다
#   out/wrong/wrong.key                  위조 실험용 "다른" 서명 키
#   out/r1/  Lab Boiler Root R1 → Issuing I1 → 서버 리프 (옛 사슬)
#   out/r2/  Lab Boiler Root R2 → Issuing I2 → 서버 리프 (새 사슬)
#   out/r*/expired-chain.pem  2026-03-01에 만료된 리프 + 중간 (시각 모름 처리 실험)
#   루트·중간은 notBefore 2026-01-01로 고정, 리프는 만든 날부터 90일
set -euo pipefail
cd "$(dirname "$0")"
if [[ "${1:-}" == "--force" ]]; then rm -rf out device; fi
if [[ -f out/r2/chain.pem ]]; then echo "이미 있음: out/ (다시 만들려면 --force)"; exit 0; fi
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }

mkdir -p out/ota out/wrong
key out/ota/ota_sign.key
openssl pkey -in out/ota/ota_sign.key -pubout -out out/ota/ota_sign.pub
key out/wrong/wrong.key

chain() {  # $1=r1|r2  $2=R1|R2  $3=I1|I2
  local d="out/$1"; mkdir -p "$d"
  key "$d/root.key"
  openssl req -x509 -new -key "$d/root.key" -sha256 -not_before 20260101000000Z -not_after 20451231235959Z \
    -subj "/C=KR/O=Lab Boiler Example/CN=Lab Boiler Root $2" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out "$d/root.crt"
  key "$d/inter.key"
  openssl req -new -key "$d/inter.key" -subj "/C=KR/O=Lab Boiler Example/CN=Lab Boiler Issuing $3" -out "$d/inter.csr"
  printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" \
    "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" > "$d/inter.ext"
  openssl x509 -req -in "$d/inter.csr" -CA "$d/root.crt" -CAkey "$d/root.key" -CAcreateserial \
    -not_before 20260101000000Z -not_after 20301231235959Z -sha256 -extfile "$d/inter.ext" -out "$d/inter.crt" 2>/dev/null
  key "$d/leaf.key"
  openssl req -new -key "$d/leaf.key" -subj "/CN=api.boiler.lab.example" -out "$d/leaf.csr"
  printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:api.boiler.lab.example,DNS:localhost,IP:127.0.0.1" \
    "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" > "$d/leaf.ext"
  openssl x509 -req -in "$d/leaf.csr" -CA "$d/inter.crt" -CAkey "$d/inter.key" -CAcreateserial \
    -days 90 -sha256 -extfile "$d/leaf.ext" -out "$d/leaf.crt" 2>/dev/null
  cat "$d/leaf.crt" "$d/inter.crt" > "$d/chain.pem"
  # 빌드 시각보다 먼저 만료된 리프(시각 모름 처리 실험용)
  openssl x509 -req -in "$d/leaf.csr" -CA "$d/inter.crt" -CAkey "$d/inter.key" -CAcreateserial \
    -not_before 20260101000000Z -not_after 20260301000000Z -sha256 -extfile "$d/leaf.ext" -out "$d/expired-leaf.crt" 2>/dev/null
  cat "$d/expired-leaf.crt" "$d/inter.crt" > "$d/expired-chain.pem"
  rm -f "$d"/*.csr "$d"/*.srl "$d"/*.ext
}
chain r1 R1 I1
chain r2 R2 I2
echo "만듦: $(pwd)/out"
openssl verify -CAfile out/r1/root.crt -untrusted out/r1/inter.crt out/r1/leaf.crt
openssl verify -CAfile out/r2/root.crt -untrusted out/r2/inter.crt out/r2/leaf.crt

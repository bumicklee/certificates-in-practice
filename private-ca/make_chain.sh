#!/usr/bin/env bash
# 사설 CA 3단 사슬(루트 → 중간 → 리프)을 만든다. 실습 전용, 가짜 이름만 쓴다.
#
#   ./make_chain.sh            # out/ 에 만든다 (이미 있으면 그대로 둔다)
#   ./make_chain.sh --force    # out/ 을 지우고 다시 만든다
#   OUT=/tmp/x ./make_chain.sh # 다른 폴더에
#
# 만들어지는 것
#   out/root.key  root.crt         루트 CA (ECDSA P-256, 10년, pathlen:1)
#   out/inter.key inter.crt        중간 CA (5년, pathlen:0)
#   out/leaf.key  leaf.crt         서버 리프 (90일, SAN: shop.lab.example, localhost, 127.0.0.1)
#   out/client.key client.crt      클라이언트 리프 (90일, EKU clientAuth, SAN URI spiffe://lab.example/orders)
#   out/chain.pem                  leaf + inter (서버가 보내는 사슬)
#   out/ca-bundle.pem              root (클라이언트가 믿는 저장소)
set -euo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-out}"
if [[ "${1:-}" == "--force" ]]; then rm -rf "$OUT"; fi
if [[ -f "$OUT/leaf.crt" ]]; then echo "이미 있음: $OUT (다시 만들려면 --force)"; exit 0; fi
mkdir -p "$OUT"; cd "$OUT"

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }

# 1) 루트
key root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 \
  -subj "/C=KR/O=Lab Example Trust/CN=Lab Example Root CA R1" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root.crt

# 2) 중간
key inter.key
openssl req -new -key inter.key -subj "/C=KR/O=Lab Example Trust/CN=Lab Example Issuing CA I1" -out inter.csr
cat > inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -days 1825 -sha256 -extfile inter.ext -out inter.crt 2>/dev/null

# 3) 서버 리프
key leaf.key
openssl req -new -key leaf.key -subj "/CN=shop.lab.example" -out leaf.csr
cat > leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:shop.lab.example,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in leaf.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
  -days 90 -sha256 -extfile leaf.ext -out leaf.crt 2>/dev/null

# 4) 클라이언트 리프 (mTLS용)
key client.key
openssl req -new -key client.key -subj "/CN=orders" -out client.csr
cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://lab.example/orders
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in client.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
  -days 90 -sha256 -extfile client.ext -out client.crt 2>/dev/null

cat leaf.crt inter.crt > chain.pem
cp root.crt ca-bundle.pem
rm -f ./*.csr ./*.srl

echo "만듦: $(pwd)"
openssl verify -CAfile root.crt -untrusted inter.crt leaf.crt client.crt

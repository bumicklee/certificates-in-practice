#!/usr/bin/env bash
# 13·14·15편용 추가 인증서를 out/ 에 만든다. ../private-ca/out/ 은 읽기만 한다(고치지 않는다).
#   out/ok/          orders 클라이언트(private-ca가 만든 client.crt) + 중간 CA 사슬
#   out/payments/    같은 사내 중간 CA가 발급, SAN URI spiffe://lab.example/payments (인증은 되지만 /orders 인가는 안 됨)
#   out/expired/     같은 중간 CA, SAN은 orders, 그런데 이미 만료
#   out/otherca/     전혀 다른 루트(Other Lab Root)가 발급한 orders 인증서
#   out/ca2/         교체용 새 루트 R2 + 그 아래 orders 클라이언트 (14·15편 무중단 교체)
#   out/pg/          PostgreSQL용 자체 서명 인증서(CN=wrong.example) (14·15편 sslmode 비교)
set -euo pipefail
cd "$(dirname "$0")"
PCA=../private-ca/out
[[ -f $PCA/client.crt ]] || { echo "먼저 ../private-ca/make_chain.sh 를 돌리세요"; exit 1; }
if [[ "${1:-}" == "--force" ]]; then rm -rf out; fi
if [[ -f out/ok/chain.pem ]]; then echo "이미 있음: out (다시: --force)"; exit 0; fi
mkdir -p out/{ok,payments,expired,otherca,ca2,pg}
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }
cliext() { cat > "$1" <<EOT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:$2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOT
}
# 클라이언트 인증서: sign <dir> <CN> <SAN URI> <CA crt> <CA key> [openssl x509 추가 옵션...]
sign() { local d=$1 cn=$2 uri=$3 ca=$4 cakey=$5; shift 5
  key $d/client.key
  openssl req -new -key $d/client.key -subj "/CN=$cn" -out $d/client.csr
  cliext $d/client.ext "$uri"
  openssl x509 -req -in $d/client.csr -CA $ca -CAkey $cakey -CAcreateserial -CAserial $d/ca.srl \
    -sha256 -extfile $d/client.ext -out $d/client.crt "$@" 2>/dev/null
  rm -f $d/client.csr $d/ca.srl
}
# 루트 하나 만들기: mkroot <dir> <CN>
mkroot() { key $1/root.key
  openssl req -x509 -new -key $1/root.key -sha256 -days 3650 -subj "/C=KR/O=$2/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out $1/root.crt; }

# ok: 기존 클라이언트 인증서 + 중간 CA를 이어 붙인 사슬만 만든다(키는 복사)
cat $PCA/client.crt $PCA/inter.crt > out/ok/chain.pem
cp $PCA/client.key out/ok/client.key; chmod 600 out/ok/client.key

sign out/payments payments spiffe://lab.example/payments $PCA/inter.crt $PCA/inter.key -days 90
cat out/payments/client.crt $PCA/inter.crt > out/payments/chain.pem

sign out/expired orders spiffe://lab.example/orders $PCA/inter.crt $PCA/inter.key \
  -not_before 20260901000000Z -not_after 20261001000000Z
cat out/expired/client.crt $PCA/inter.crt > out/expired/chain.pem

mkroot out/otherca "Other Lab Root"
sign out/otherca orders spiffe://lab.example/orders out/otherca/root.crt out/otherca/root.key -days 90
cp out/otherca/client.crt out/otherca/chain.pem

mkroot out/ca2 "Lab Example Root R2"
sign out/ca2 orders spiffe://lab.example/orders out/ca2/root.crt out/ca2/root.key -days 90
cp out/ca2/client.crt out/ca2/chain.pem

key out/pg/server.key
openssl req -x509 -new -key out/pg/server.key -sha256 -days 30 -subj "/CN=wrong.example" \
  -addext "subjectAltName=DNS:wrong.example" -out out/pg/server.crt

rm -f out/*/client.ext
echo "== 만든 클라이언트 인증서"
for d in ok payments expired otherca ca2; do
  c=out/$d/chain.pem
  printf '%-9s ' $d; openssl x509 -in $c -noout -issuer -enddate -ext subjectAltName 2>/dev/null | tr '\n' ' ' | sed 's/X509v3 Subject Alternative Name: *//; s/  */ /g'; echo
done

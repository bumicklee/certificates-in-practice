#!/usr/bin/env bash
# 일부러 깨뜨린 사슬 다섯 가지(+ 위험한 통과 한 가지)를 out/ 에 만든다. 실습 전용, 가짜 이름만 쓴다.
#
#   ./make_broken.sh          # 이미 있으면 그대로 둔다
#   ./make_broken.sh --force  # out/ 을 지우고 다시 만든다
#
# out/base/                 정상 3단 사슬 (../private-ca/make_chain.sh 를 OUT 으로 불러 만든다. private-ca 는 건드리지 않는다)
# out/1-expired/            유효 기간이 끝난 리프
# out/2-wrong-issuer/       다른 CA(Other Issuing CA)가 서명한 리프
# out/3-san-mismatch/       SAN이 other.lab.example 인 리프 (shop.lab.example 로 접속)
# out/4-missing-inter/      정상 리프인데 서버가 중간 인증서를 빠뜨린 경우 (리프만 보냄)
# out/5-leaf-ca-true/       CA:TRUE 가 잘못 들어간 리프가 evil.lab.example 인증서를 서명
# out/5b-careless/          pathlen·keyUsage 제한이 없는 "허술한 CA" 에서 같은 일을 하면? (검증이 통과해 버린다)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
if [[ "${1:-}" == "--force" ]]; then rm -rf out; fi
if [[ -f out/5b-careless/evil.crt ]]; then echo "이미 있음: $HERE/out (다시 만들려면 --force)"; exit 0; fi
mkdir -p out

# 0) 정상 사슬: 공용 스크립트를 내 폴더로 출력
OUT="$HERE/out/base" ../private-ca/make_chain.sh >/dev/null
B=out/base

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }
leafext() { # $1=파일 $2=SAN
  cat > "$1" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
}

# 1) 만료된 리프: notAfter 를 과거로
d=out/1-expired; mkdir -p $d; key $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=shop.lab.example" -out $d/leaf.csr
leafext $d/leaf.ext "DNS:shop.lab.example,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in $d/leaf.csr -CA $B/inter.crt -CAkey $B/inter.key -CAcreateserial \
  -not_before 20250101000000Z -not_after 20250401000000Z -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
cat $d/leaf.crt $B/inter.crt > $d/chain.pem

# 2) 잘못된 발급자: 우리가 믿지 않는 다른 루트·중간이 서명
d=out/2-wrong-issuer; mkdir -p $d
key $d/other-root.key
openssl req -x509 -new -key $d/other-root.key -sha256 -days 3650 -subj "/C=KR/O=Other Example/CN=Other Example Root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" -addext "keyUsage=critical,keyCertSign,cRLSign" -out $d/other-root.crt
key $d/other-inter.key
openssl req -new -key $d/other-inter.key -subj "/C=KR/O=Other Example/CN=Other Issuing CA" -out $d/other-inter.csr
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > $d/inter.ext
openssl x509 -req -in $d/other-inter.csr -CA $d/other-root.crt -CAkey $d/other-root.key -CAcreateserial -days 1825 -sha256 -extfile $d/inter.ext -out $d/other-inter.crt 2>/dev/null
key $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=shop.lab.example" -out $d/leaf.csr
leafext $d/leaf.ext "DNS:shop.lab.example,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in $d/leaf.csr -CA $d/other-inter.crt -CAkey $d/other-inter.key -CAcreateserial -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
cat $d/leaf.crt $d/other-inter.crt > $d/chain.pem

# 3) SAN 불일치: other.lab.example 로만 발급
d=out/3-san-mismatch; mkdir -p $d; key $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=shop.lab.example" -out $d/leaf.csr   # CN 은 맞지만 SAN 이 다르다
leafext $d/leaf.ext "DNS:other.lab.example"
openssl x509 -req -in $d/leaf.csr -CA $B/inter.crt -CAkey $B/inter.key -CAcreateserial -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
cat $d/leaf.crt $B/inter.crt > $d/chain.pem

# 4) 중간 누락: 정상 리프를 쓰되 사슬 파일에 리프만
d=out/4-missing-inter; mkdir -p $d
cp $B/leaf.crt $d/leaf.crt; cp $B/leaf.key $d/leaf.key; chmod 600 $d/leaf.key
cp $B/leaf.crt $d/chain.pem

# 5) CA:TRUE 리프: 정상 중간(pathlen:0)이 실수로 CA:TRUE 리프를 발급 → 그 리프가 evil.lab.example 서명
d=out/5-leaf-ca-true; mkdir -p $d; key $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=shop.lab.example" -out $d/leaf.csr
cat > $d/leaf.ext <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign
extendedKeyUsage=serverAuth
subjectAltName=DNS:shop.lab.example
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in $d/leaf.csr -CA $B/inter.crt -CAkey $B/inter.key -CAcreateserial -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
key $d/evil.key
openssl req -new -key $d/evil.key -subj "/CN=evil.lab.example" -out $d/evil.csr
leafext $d/evil.ext "DNS:evil.lab.example"
openssl x509 -req -in $d/evil.csr -CA $d/leaf.crt -CAkey $d/leaf.key -CAcreateserial -days 30 -sha256 -extfile $d/evil.ext -out $d/evil.crt 2>/dev/null
cat $d/evil.crt $d/leaf.crt $B/inter.crt > $d/chain.pem

# 5b) 허술한 CA: 루트·중간에 pathlen 이 없고, 리프에도 CA:TRUE + keyCertSign. 이름 제약도 없다.
d=out/5b-careless; mkdir -p $d
key $d/root.key
openssl req -x509 -new -key $d/root.key -sha256 -days 3650 -subj "/C=KR/O=Careless Example/CN=Careless Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out $d/root.crt
key $d/inter.key
openssl req -new -key $d/inter.key -subj "/C=KR/O=Careless Example/CN=Careless Issuing CA" -out $d/inter.csr
printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > $d/inter.ext
openssl x509 -req -in $d/inter.csr -CA $d/root.crt -CAkey $d/root.key -CAcreateserial -days 1825 -sha256 -extfile $d/inter.ext -out $d/inter.crt 2>/dev/null
key $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=shop.lab.example" -out $d/leaf.csr
cp out/5-leaf-ca-true/leaf.ext $d/leaf.ext
openssl x509 -req -in $d/leaf.csr -CA $d/inter.crt -CAkey $d/inter.key -CAcreateserial -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
key $d/evil.key
openssl req -new -key $d/evil.key -subj "/CN=evil.lab.example" -out $d/evil.csr
leafext $d/evil.ext "DNS:evil.lab.example"
openssl x509 -req -in $d/evil.csr -CA $d/leaf.crt -CAkey $d/leaf.key -CAcreateserial -days 30 -sha256 -extfile $d/evil.ext -out $d/evil.crt 2>/dev/null
cat $d/evil.crt $d/leaf.crt $d/inter.crt > $d/chain.pem

find out -name '*.csr' -delete; find out -name '*.srl' -delete
echo "만듦: $HERE/out"
ls out

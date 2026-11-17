#!/usr/bin/env bash
# 중간 CA 교체 두 가지를 흉내 낸다(사설 루트로 새 중간을 서명. lab/private-ca 파일은 읽기만 한다).
#   out/rot-backup/   예비 키(backup-inter.key)로 새 중간 CA를 세운 경우
#   out/rot-unknown/  핀에 없는 새 키로 중간 CA를 세운 경우
set -euo pipefail
cd "$(dirname "$0")"
CA=../private-ca/out
mk() { # $1=폴더 $2=중간 키
  local d=$1; mkdir -p $d
  printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > $d/inter.ext
  openssl req -new -key $2 -subj "/C=KR/O=Lab Example Trust/CN=Lab Example Issuing CA I2" -out $d/inter.csr
  openssl x509 -req -in $d/inter.csr -CA $CA/root.crt -CAkey $CA/root.key -set_serial 0x$(openssl rand -hex 8) -days 1825 -sha256 -extfile $d/inter.ext -out $d/inter.crt 2>/dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $d/leaf.key 2>/dev/null; chmod 600 $d/leaf.key
  openssl req -new -key $d/leaf.key -subj "/CN=api.lab.example" -out $d/leaf.csr
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:api.lab.example\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > $d/leaf.ext
  openssl x509 -req -in $d/leaf.csr -CA $d/inter.crt -CAkey $2 -set_serial 0x$(openssl rand -hex 8) -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
  cat $d/leaf.crt $d/inter.crt > $d/chain.pem; rm -f $d/*.csr
}
mkdir -p out/rot-unknown
[[ -f out/rot-unknown/inter.key ]] || { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out out/rot-unknown/inter.key 2>/dev/null; chmod 600 out/rot-unknown/inter.key; }
mk out/rot-backup out/backup-inter.key
mk out/rot-unknown out/rot-unknown/inter.key
# 지금 사슬(api.lab.example 용 리프를 지금 중간 CA로)
d=out/current; mkdir -p $d
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $d/leaf.key 2>/dev/null; chmod 600 $d/leaf.key
openssl req -new -key $d/leaf.key -subj "/CN=api.lab.example" -out $d/leaf.csr
cp out/rot-backup/leaf.ext $d/leaf.ext
openssl x509 -req -in $d/leaf.csr -CA $CA/inter.crt -CAkey $CA/inter.key -set_serial 0x$(openssl rand -hex 8) -days 90 -sha256 -extfile $d/leaf.ext -out $d/leaf.crt 2>/dev/null
cat $d/leaf.crt $CA/inter.crt > $d/chain.pem; rm -f $d/*.csr
echo "만듦: out/current out/rot-backup out/rot-unknown"

#!/usr/bin/env bash
# 수업 3-2(교차 서명·중간 누락)과 수업 7-1(CA:TRUE 리프) 시연용 사슬을 out/ 에 만든다.
# 공용 사슬(../private-ca/out)은 읽기만 하고 고치지 않는다.
#   ./make_demo.sh          # 만들기(있으면 다시 만든다)
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out; mkdir -p out; cd out
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }
root() { # $1=이름 $2=CN
  key "$1.key"
  openssl req -x509 -new -key "$1.key" -sha256 -days 3650 -subj "/O=Lab Example Trust/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out "$1.crt"
}
cat > ca.ext <<'X'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > leaf.ext <<'X'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.lab.example
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X

# --- 교차 서명: 두 루트(옛 루트 X, 새 루트 Y)가 같은 중간 CA 키에 각각 서명한다 ---
root rootX "Lab Old Root X1"
root rootY "Lab New Root Y1"
key inter.key
openssl req -new -key inter.key -subj "/O=Lab Example Trust/CN=Lab Cross Issuing CA C1" -out inter.csr
openssl x509 -req -in inter.csr -CA rootY.crt -CAkey rootY.key -CAcreateserial -days 1825 -sha256 -extfile ca.ext -out inter-by-Y.crt 2>/dev/null
openssl x509 -req -in inter.csr -CA rootX.crt -CAkey rootX.key -CAcreateserial -days 1825 -sha256 -extfile ca.ext -out inter-by-X.crt 2>/dev/null
key leaf.key
openssl req -new -key leaf.key -subj "/CN=api.lab.example" -out leaf.csr
openssl x509 -req -in leaf.csr -CA inter-by-Y.crt -CAkey inter.key -CAcreateserial -days 90 -sha256 -extfile leaf.ext -out leaf.crt 2>/dev/null

# 수업 7-1: AIA·CRL 배포 지점이 들어간 리프 (주소는 가짜 실습 도메인)
cat > leaf-aia.ext <<'X'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.lab.example
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=caIssuers;URI:http://pki.lab.example/c1.crt
crlDistributionPoints=URI:http://pki.lab.example/c1.crl
certificatePolicies=2.23.140.1.2.1
X
openssl x509 -req -in leaf.csr -CA inter-by-Y.crt -CAkey inter.key -CAcreateserial -days 90 -sha256 -extfile leaf-aia.ext -out leaf-aia.crt 2>/dev/null

# 새 루트 Y 자체를 옛 루트 X가 교차 서명한 인증서 (Let's Encrypt ISRG Root X1 ← DST Root CA X3 방식)
cat > xroot.ext <<'X'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
openssl req -new -key rootY.key -subj "/O=Lab Example Trust/CN=Lab New Root Y1" -out rootY.csr
openssl x509 -req -in rootY.csr -CA rootX.crt -CAkey rootX.key -CAcreateserial -days 1825 -sha256 -extfile xroot.ext -out rootY-by-X.crt 2>/dev/null

# --- 수업 7-1: CA:TRUE 가 잘못 들어간 "리프" ---
# (a) pathlen 제한이 없는 중간 CA 아래에 CA:TRUE 리프 -> 그 리프가 남의 이름을 찍어 낸다
cat > ca-nolimit.ext <<'X'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > badleaf.ext <<'X'
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign
extendedKeyUsage=serverAuth
subjectAltName=DNS:blog.lab.example
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > minted.ext <<'X'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:bank.lab.example
authorityKeyIdentifier=keyid
X
root rootN "Lab NoLimit Root N1"
key interN.key
openssl req -new -key interN.key -subj "/O=Lab Example Trust/CN=Lab NoLimit Issuing N1" -out interN.csr
openssl x509 -req -in interN.csr -CA rootN.crt -CAkey rootN.key -CAcreateserial -days 1825 -sha256 -extfile ca-nolimit.ext -out interN.crt 2>/dev/null
key badleaf.key
openssl req -new -key badleaf.key -subj "/CN=blog.lab.example" -out badleaf.csr
openssl x509 -req -in badleaf.csr -CA interN.crt -CAkey interN.key -CAcreateserial -days 90 -sha256 -extfile badleaf.ext -out badleaf.crt 2>/dev/null
key minted.key
openssl req -new -key minted.key -subj "/CN=bank.lab.example" -out minted.csr
openssl x509 -req -in minted.csr -CA badleaf.crt -CAkey badleaf.key -CAcreateserial -days 30 -sha256 -extfile minted.ext -out minted.crt 2>/dev/null
# (b) 공용 사슬의 정상 리프(CA:FALSE) 키로 같은 짓을 해 본다
openssl x509 -req -in minted.csr -CA ../../private-ca/out/leaf.crt -CAkey ../../private-ca/out/leaf.key \
  -CAserial minted-by-shop.srl -CAcreateserial -days 30 -sha256 -extfile minted.ext -out minted-by-shop.crt 2>/dev/null
rm -f ./*.csr ./*.srl
echo "만듦: $(pwd)"

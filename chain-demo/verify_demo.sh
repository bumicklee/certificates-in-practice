#!/usr/bin/env bash
# make_demo.sh 로 만든 사슬과 공용 사슬을 openssl verify 로 검사한다. 실패도 그대로 보여 준다.
cd "$(dirname "$0")"
P=../private-ca/out; D=out
run() { echo "\$ $*"; "$@" 2>&1; echo "(exit=$?)"; echo; }

echo "## 1. 공용 사슬: 정상 / 중간 누락"
run openssl verify -CAfile $P/ca-bundle.pem -untrusted $P/inter.crt $P/leaf.crt
run openssl verify -CAfile $P/ca-bundle.pem $P/leaf.crt
run openssl verify -show_chain -CAfile $P/ca-bundle.pem -untrusted $P/inter.crt $P/leaf.crt

echo "## 2. 교차 서명: 같은 중간 CA 키, 서로 다른 두 루트"
for f in $D/inter-by-Y.crt $D/inter-by-X.crt; do
  echo "--- $f"; openssl x509 -in $f -noout -subject -issuer -ext subjectKeyIdentifier,authorityKeyIdentifier; done
echo "--- leaf"; openssl x509 -in $D/leaf.crt -noout -subject -issuer -ext authorityKeyIdentifier; echo
run openssl verify -show_chain -CAfile $D/rootY.crt -untrusted $D/inter-by-Y.crt $D/leaf.crt
run openssl verify -show_chain -CAfile $D/rootX.crt -untrusted $D/inter-by-X.crt $D/leaf.crt
echo "# 서버가 두 중간 인증서를 모두 보내면, 클라이언트는 자기가 믿는 루트로 가는 길을 고른다"
cat $D/inter-by-Y.crt $D/inter-by-X.crt > $D/both-inters.pem
run openssl verify -show_chain -CAfile $D/rootX.crt -untrusted $D/both-inters.pem $D/leaf.crt
run openssl verify -show_chain -CAfile $D/rootY.crt -untrusted $D/both-inters.pem $D/leaf.crt
echo "# 순서를 바꿔 X 쪽 중간을 앞에 두면"
cat $D/inter-by-X.crt $D/inter-by-Y.crt > $D/both-inters-xfirst.pem
run openssl verify -show_chain -CAfile $D/rootX.crt -untrusted $D/both-inters-xfirst.pem $D/leaf.crt
run openssl verify -show_chain -CAfile $D/rootY.crt -untrusted $D/both-inters-xfirst.pem $D/leaf.crt
echo "# 클라이언트가 두 루트를 모두 믿으면 순서와 상관없이 통과한다"
cat $D/rootX.crt $D/rootY.crt > $D/both-roots.pem
run openssl verify -show_chain -CAfile $D/both-roots.pem -untrusted $D/both-inters.pem $D/leaf.crt
echo "# 옛 루트만 믿는 클라이언트에 새 루트 쪽 중간만 보내면"
run openssl verify -CAfile $D/rootX.crt -untrusted $D/inter-by-Y.crt $D/leaf.crt

echo "## 3. 루트를 교차 서명: 서버는 한 사슬(leaf + inter-by-Y + rootY-by-X)만 보낸다"
cat $D/inter-by-Y.crt $D/rootY-by-X.crt > $D/served-chain.pem
run openssl verify -show_chain -CAfile $D/rootY.crt -untrusted $D/served-chain.pem $D/leaf.crt
run openssl verify -show_chain -CAfile $D/rootX.crt -untrusted $D/served-chain.pem $D/leaf.crt

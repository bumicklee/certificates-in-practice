#!/usr/bin/env bash
# 수업 7-1: CA:TRUE 가 잘못 들어간 리프가 남의 이름(bank.lab.example) 인증서를 찍어 내는지 본다.
cd "$(dirname "$0")"
P=../private-ca/out; D=out
run() { echo "\$ $*"; "$@" 2>&1; echo "(exit=$?)"; echo; }
echo "# CA:TRUE 가 잘못 들어간 리프(blog.lab.example)가 bank.lab.example 인증서를 찍어 냈다"
run openssl x509 -in $D/badleaf.crt -noout -subject -ext basicConstraints
run openssl x509 -in $D/minted.crt -noout -subject -issuer
echo "# (a) 위쪽 중간 CA에 pathlen 제한이 없으면 (untrustedN.pem = interN.crt + badleaf.crt)"
cat $D/interN.crt $D/badleaf.crt > $D/untrustedN.pem
run openssl verify -show_chain -verify_hostname bank.lab.example -CAfile $D/rootN.crt -untrusted $D/untrustedN.pem $D/minted.crt
echo "# (b) 공용 사슬의 정상 리프(CA:FALSE) 키로 같은 짓을 하면 (untrustedP.pem = inter.crt + leaf.crt)"
cat $P/inter.crt $P/leaf.crt > $D/untrustedP.pem
run openssl verify -verify_hostname bank.lab.example -CAfile $P/ca-bundle.pem -untrusted $D/untrustedP.pem $D/minted-by-shop.crt

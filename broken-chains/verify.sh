#!/usr/bin/env bash
# 깨뜨린 사슬을 openssl verify 로 하나씩 검증한다. 실패가 정상이다(5b만 "통과해서 위험").
set -uo pipefail
cd "$(dirname "$0")/out"
R=base/root.crt
run() { echo "== $1"; shift; echo "\$ openssl verify $*"; openssl verify "$@" 2>&1; echo; }

run "0 정상(base)"          -CAfile $R -untrusted base/inter.crt -verify_hostname shop.lab.example base/leaf.crt
run "1 만료된 리프"          -CAfile $R -untrusted base/inter.crt 1-expired/leaf.crt
run "2 잘못된 발급자"        -CAfile $R -untrusted 2-wrong-issuer/other-inter.crt 2-wrong-issuer/leaf.crt
run "3 SAN 불일치"           -CAfile $R -untrusted base/inter.crt -verify_hostname shop.lab.example 3-san-mismatch/leaf.crt
run "4 중간 누락"            -CAfile $R 4-missing-inter/leaf.crt
cat 5-leaf-ca-true/leaf.crt base/inter.crt > _untrusted-5-untrusted.pem
run "5 CA:TRUE 리프가 서명한 evil" -CAfile $R -untrusted _untrusted-5-untrusted.pem 5-leaf-ca-true/evil.crt
cat 5b-careless/leaf.crt 5b-careless/inter.crt > _untrusted-5b-untrusted.pem
run "5b 허술한 CA에서 같은 일" -CAfile 5b-careless/root.crt -untrusted _untrusted-5b-untrusted.pem 5b-careless/evil.crt
rm -f _untrusted-5-untrusted.pem _untrusted-5b-untrusted.pem

#!/usr/bin/env bash
# 7·8편: 계정 키와 인증서 키는 다른 키다. 개인키 내용은 찍지 않고 공개키 지문만 비교한다.
set -euo pipefail
cd "$(dirname "$0")"
W=pki-lab-acme-web; A=accounts/pebble_14000/admin@lab.example
echo "== lego 저장소 구조"; docker exec $W sh -c 'cd /data/lego && find . -type f | sort'
fp() { docker exec $W cat "/data/lego/$1" | openssl pkey -pubout 2>/dev/null | openssl dgst -sha256 -r | cut -c1-32; }
echo; echo "== 공개키 SHA-256 지문(앞 32자)"
echo "계정 키       : $(fp $A/admin@lab.example.key)"
echo "shop 인증서 키: $(fp certificates/shop.lab.example.key)"
echo "와일드카드 키 : $(fp certificates/_.lab.example.key)"
echo; echo "== 인증서 안의 공개키 지문(shop)"
docker exec $W cat /data/lego/certificates/shop.lab.example.crt | openssl x509 -noout -pubkey | openssl dgst -sha256 -r | cut -c1-32
echo; echo "== account.json (계정 URL)"; docker exec $W cat /data/lego/$A/account.json | grep -E '"(uri|status)"|"email"'
echo; echo "== 파일 권한"; docker exec $W ls -l /data/lego/$A/admin@lab.example.key /data/lego/certificates/shop.lab.example.key

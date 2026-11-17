#!/usr/bin/env bash
# 실습 인증서로 앱 자원을 만든다(실습 전용). 인자: broken-chains/out 폴더
#   ./make_assets.sh <…>/broken-chains/out
# 만드는 것: res/raw/lab_root.pem(신뢰할 실습 루트), assets/client.p12(실습 클라이언트 키+인증서+중간),
#            res/xml/nsc_pin_right.xml · nsc_pin_wrong.xml(핀 = 중간 CA 공개키의 SHA-256)
set -euo pipefail
OUT="$1"; HERE="$(cd "$(dirname "$0")" && pwd)"; B="$OUT/base"
cp "$B/root.crt" "$HERE/app/src/main/res/raw/lab_root.pem"
openssl pkcs12 -export -inkey "$B/client.key" -in "$B/client.crt" -certfile "$B/inter.crt" \
  -name lab-client -passout pass:lab-only-pass -out "$HERE/app/src/main/assets/client.p12"
spki() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64; }
RIGHT=$(spki "$B/inter.crt"); WRONG=$(spki "$OUT/2-wrong-issuer/other-inter.crt")
for kind in right wrong; do
  pin=$RIGHT; [[ $kind == wrong ]] && pin=$WRONG
  cat > "$HERE/app/src/main/res/xml/nsc_pin_$kind.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<!-- nsc_main + localhost에 핀 하나($kind). 핀 = 중간 CA 공개키(SPKI) SHA-256 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">localhost</domain>
        <trust-anchors><certificates src="@raw/lab_root" /></trust-anchors>
        <pin-set>
            <pin digest="SHA-256">$pin</pin>
        </pin-set>
    </domain-config>
</network-security-config>
XML
done
echo "right pin (Lab Example Issuing CA I1): $RIGHT"
echo "wrong pin (Other Issuing CA):          $WRONG"

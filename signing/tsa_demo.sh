#!/usr/bin/env bash
# 로컬 TSA(RFC 3161) 타임스탬프 시연(6편). 모두 out/ 아래에 만든다. 네트워크 없음.
#
#  1) 문서 서명용 사슬: 서명 루트 → 서명자 인증서(수명 1일)
#  2) TSA 사슬: TSA 루트 → TSA 인증서(EKU critical timeStamping)
#  3) 문서에 CMS 서명 → 그 서명 파일에 타임스탬프 요청(.tsq) → 응답(.tsr) → 검증
#  4) "서명자 인증서가 만료된 뒤"(-attime 미래)에 검증하면 실패,
#     타임스탬프가 증명한 시각(genTime)에 검증하면 통과
#
#   ./tsa_demo.sh
set -uo pipefail
cd "$(dirname "$0")"
rm -rf out; mkdir -p out; cd out
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }
run() { echo "\$ $*"; "$@" 2>&1; echo "(exit=$?)"; echo; }

# --- 1) 문서 서명자 사슬 ---
key sign-root.key
openssl req -x509 -new -key sign-root.key -sha256 -days 3650 -subj "/O=Lab Example Trust/CN=Lab Signing Root S1" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out sign-root.crt
key signer.key
openssl req -new -key signer.key -subj "/O=Lab Example Corp/CN=Kim Lab (FAKE signer)" -out signer.csr
cat > signer.ext <<'X'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectAltName=email:signer@lab.example
X
openssl x509 -req -in signer.csr -CA sign-root.crt -CAkey sign-root.key -CAcreateserial -days 1 -sha256 -extfile signer.ext -out signer.crt 2>/dev/null

# --- 2) TSA 사슬 ---
key tsa-root.key
openssl req -x509 -new -key tsa-root.key -sha256 -days 3650 -subj "/O=Lab Example Trust/CN=Lab TSA Root T1" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out tsa-root.crt
key tsa.key
openssl req -new -key tsa.key -subj "/O=Lab Example Trust/CN=Lab Time Stamping Unit 1" -out tsa.csr
cat > tsa.ext <<'X'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
X
openssl x509 -req -in tsa.csr -CA tsa-root.crt -CAkey tsa-root.key -CAcreateserial -days 3650 -sha256 -extfile tsa.ext -out tsa.crt 2>/dev/null
cat > tsa.cnf <<'X'
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir               = .
serial            = ./tsa-serial
crypto_device     = builtin
certs             = ./tsa-root.crt
signer_digest     = sha256
default_policy    = 1.3.6.1.4.1.55555.1.1
other_policies    = 1.3.6.1.4.1.55555.1.2
digests           = sha256, sha384, sha512
accuracy          = secs:1
ordering          = yes
tsa_name          = yes
ess_cert_id_chain = no
ess_cert_id_alg   = sha256
X
echo 01 > tsa-serial
rm -f ./*.csr ./*.srl

echo "## 서명자 인증서와 TSA 인증서"
run openssl x509 -in signer.crt -noout -subject -dates
run openssl x509 -in tsa.crt -noout -subject -ext extendedKeyUsage

echo "## 3) 문서 서명 → 타임스탬프 요청·응답·검증"
printf 'FAKE 계약서 SN-0000-0042\n금액: 1,000,000원\n' > contract.txt
run openssl cms -sign -binary -in contract.txt -signer signer.crt -inkey signer.key -md sha256 -outform DER -out contract.p7s
run openssl ts -query -data contract.p7s -sha256 -cert -out req.tsq
run openssl ts -query -in req.tsq -text
run openssl ts -reply -config tsa.cnf -queryfile req.tsq -inkey tsa.key -signer tsa.crt -out resp.tsr
run openssl ts -reply -in resp.tsr -text
run openssl ts -verify -data contract.p7s -in resp.tsr -CAfile tsa-root.crt -untrusted tsa.crt

echo "## 4) 시각을 바꿔 가며 서명 검증"
GEN=$(openssl ts -reply -in resp.tsr -text 2>/dev/null | sed -n 's/^Time stamp: //p')
GEN_EPOCH=$(date -j -u -f "%b %e %H:%M:%S %Y GMT" "$GEN" +%s)
END=$(openssl x509 -in signer.crt -noout -enddate | sed 's/notAfter=//')
LATER=$(( $(date -j -u -f "%b %e %H:%M:%S %Y GMT" "$END" +%s) + 86400 ))
echo "타임스탬프 genTime = $GEN (epoch $GEN_EPOCH)"
echo "서명자 notAfter    = $END"
echo "검증 시각(만료 하루 뒤) = $(date -u -r $LATER '+%Y-%m-%d %H:%M:%S UTC') (epoch $LATER)"; echo
echo "# 지금 검증"
run openssl cms -verify -binary -inform DER -in contract.p7s -content contract.txt -CAfile sign-root.crt -out /dev/null
echo "# 만료 하루 뒤의 '지금' 시각으로 검증 (타임스탬프 없이 보면)"
run openssl cms -verify -binary -inform DER -in contract.p7s -content contract.txt -CAfile sign-root.crt -attime $LATER -out /dev/null
echo "# 같은 날, 타임스탬프 토큰부터 검증 (TSA 인증서는 10년짜리라 아직 유효)"
run openssl ts -verify -data contract.p7s -in resp.tsr -CAfile tsa-root.crt -untrusted tsa.crt -attime $LATER
echo "# 그리고 서명자 인증서를 타임스탬프가 증명한 시각(genTime)에 검증"
run openssl cms -verify -binary -inform DER -in contract.p7s -content contract.txt -CAfile sign-root.crt -attime $GEN_EPOCH -out /dev/null

echo "## 5) 문서를 바꾸면"
printf 'FAKE 계약서 SN-0000-0042\n금액: 9,000,000원\n' > contract-edited.txt
run openssl cms -verify -binary -inform DER -in contract.p7s -content contract-edited.txt -CAfile sign-root.crt -out /dev/null
openssl cms -sign -binary -in contract-edited.txt -signer signer.crt -inkey signer.key -md sha256 -outform DER -out contract-edited.p7s 2>/dev/null
echo "# 바꾼 문서에 새로 서명하고 옛 타임스탬프를 붙여 보면"
run openssl ts -verify -data contract-edited.p7s -in resp.tsr -CAfile tsa-root.crt -untrusted tsa.crt

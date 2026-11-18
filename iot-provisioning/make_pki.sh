#!/usr/bin/env bash
# 수업 9-1 실습용 CA와 인증서를 out/ 에 만든다. 가짜 이름만 쓴다.
#   out/ca/root.crt               Lab IoT Root (ECDSA P-256)
#   out/ca/issuing.crt/.key       Lab IoT Device Issuing CA — 프로비저닝 서비스가 기기 인증서에 서명할 때 쓴다
#   out/broker/                   Mosquitto 서버 인증서 (SAN mqtt.iot.lab.example, localhost, 127.0.0.1)
#   out/claim/                    공용 클레임 인증서 (CN claim-factory-line-1). 공장 라인의 모든 기기가 같은 것을 가진다
#   out/svc/                      프로비저닝 서비스 (CN prov-service)
#   out/backend/                  텔레메트리 수신 백엔드 (CN telemetry-backend)
set -euo pipefail
cd "$(dirname "$0")"
if [[ "${1:-}" == "--force" ]]; then rm -rf out; fi
if [[ -f out/ca/root.crt ]]; then echo "이미 있음: out/ (다시 만들려면 --force)"; exit 0; fi
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }
mkdir -p out/ca out/broker out/claim out/svc out/backend out/devices

key out/ca/root.key
openssl req -x509 -new -key out/ca/root.key -sha256 -days 3650 \
  -subj "/C=KR/O=Lab IoT Example/CN=Lab IoT Root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" -out out/ca/root.crt
key out/ca/issuing.key
openssl req -new -key out/ca/issuing.key -subj "/C=KR/O=Lab IoT Example/CN=Lab IoT Device Issuing CA" -out out/ca/issuing.csr
printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" \
  "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" > out/ca/issuing.ext
openssl x509 -req -in out/ca/issuing.csr -CA out/ca/root.crt -CAkey out/ca/root.key -CAcreateserial \
  -days 1825 -sha256 -extfile out/ca/issuing.ext -out out/ca/issuing.crt 2>/dev/null
cat out/ca/issuing.crt out/ca/root.crt > out/ca/ca-chain.pem   # 브로커가 클라이언트 인증서를 검증할 때 쓴다

leaf() {  # $1=dir $2=CN $3=EKU $4=SAN(옵션)
  key "out/$1/$1.key"
  openssl req -new -key "out/$1/$1.key" -subj "/O=Lab IoT Example/CN=$2" -out "out/$1/$1.csr"
  { echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "extendedKeyUsage=$3"
    [[ -n "${4:-}" ]] && echo "subjectAltName=$4"; echo "authorityKeyIdentifier=keyid"; } > "out/$1/$1.ext"
  openssl x509 -req -in "out/$1/$1.csr" -CA out/ca/issuing.crt -CAkey out/ca/issuing.key -CAcreateserial \
    -days "${5:-90}" -sha256 -extfile "out/$1/$1.ext" -out "out/$1/$1.crt" 2>/dev/null
  rm -f "out/$1/$1.csr" "out/$1/$1.ext"
}
leaf broker  mqtt.iot.lab.example serverAuth "DNS:mqtt.iot.lab.example,DNS:localhost,IP:127.0.0.1"
leaf claim   claim-factory-line-1 clientAuth "" 365
leaf svc     prov-service         clientAuth
leaf backend telemetry-backend    clientAuth
cat out/broker/broker.crt out/ca/issuing.crt > out/broker/chain.pem
rm -f out/ca/*.csr out/ca/*.ext out/ca/*.srl
echo "만듦: $(pwd)/out"
openssl verify -CAfile out/ca/root.crt -untrusted out/ca/issuing.crt out/broker/broker.crt out/claim/claim.crt out/svc/svc.crt out/backend/backend.crt

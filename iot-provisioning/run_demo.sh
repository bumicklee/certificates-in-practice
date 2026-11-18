#!/usr/bin/env bash
# 수업 9-1 시나리오: 브로커·서비스·백엔드를 띄우고 성공 1 + 실패 5를 본 뒤 모두 끈다.
#   ./run_demo.sh > ../results/17-provisioning-demo.txt 2>&1
set -uo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
step() { printf '\n### %s\n' "$*"; }
run()  { printf '$ %s\n' "$*"; "$@"; }

./make_pki.sh --force >/dev/null; chmod 600 acl
rm -f out/registry.json out/*.log; rm -rf out/devices
/opt/homebrew/sbin/mosquitto -c mosquitto.conf & MQ=$!
sleep 0.7
$PY prov_service.py > out/prov_service.log 2>&1 & SV=$!
$PY telemetry_backend.py > out/backend.log 2>&1 & BE=$!
trap 'kill $SV $BE $MQ 2>/dev/null' EXIT
sleep 1.2

step "0. 인증서 없이 접속하면 TLS 단계에서 끊긴다 (require_certificate true)"
run mosquitto_pub -h 127.0.0.1 -p 18480 --cafile out/ca/root.crt -t devices/x/telemetry -m hi 2>&1 | head -2

step "1. 성공: 허용 목록에 있는 SN-0000-0001, SN-0000-0002"
run $PY device.py provision --serial SN-0000-0001
run $PY device.py provision --serial SN-0000-0002

step "2. 실패: 허용 목록에 없는 시리얼"
run $PY device.py provision --serial SN-0000-0099

step "3. 실패: 클레임 인증서로 텔레메트리 쓰기"
run $PY device.py publish --serial SN-0000-0001 --as claim --topic devices/boiler-SN-0000-0001/telemetry

step "4. 실패: 기기 A(SN-0000-0001)가 기기 B의 토픽에 쓰기"
run $PY device.py publish --serial SN-0000-0001 --as device --topic devices/boiler-SN-0000-0002/telemetry
echo "(비교: 자기 토픽)"
run $PY device.py publish --serial SN-0000-0001 --as device --topic devices/boiler-SN-0000-0001/telemetry

step "5. 실패: 이미 등록된 시리얼 재사용 (복제 기기 가정)"
run $PY device.py provision --serial SN-0000-0001

step "6. 기기 인증서로 프로비저닝 토픽 쓰기: 브로커는 통과(패턴은 모든 사용자에 적용), 서비스가 거부"
run $PY device.py publish --serial SN-0000-0002 --as device --topic '$prov/boiler-SN-0000-0002/boiler-SN-0000-0002/provision'
sleep 0.5

step "프로비저닝 서비스 로그"
cat out/prov_service.log
step "텔레메트리 백엔드가 실제로 받은 것"
cat out/backend.log
step "브로커 로그: 거부된 발행"
grep -E "Denied|OpenSSL Error|protocol error" out/mosquitto.log | sed -E 's/^[0-9]+: //'
step "레지스트리 (out/registry.json)"
cat out/registry.json
step "발급된 기기 인증서"
openssl x509 -in out/devices/SN-0000-0001/device.crt -noout -subject -issuer -dates -ext extendedKeyUsage
openssl verify -CAfile out/ca/root.crt -untrusted out/ca/issuing.crt out/devices/SN-0000-0001/device.crt
ls -l out/devices/SN-0000-0001/ | awk 'NR>1{print $1, $NF}'

kill $SV $BE $MQ 2>/dev/null; wait 2>/dev/null
echo; echo "브로커·서비스·백엔드 종료"

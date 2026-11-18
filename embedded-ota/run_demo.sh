#!/usr/bin/env bash
# 수업 8-4 시나리오 전체: 이미지 만들기 → 공장 출고 → 루트 교체 → OTA(정상·위조·롤백·자체 시험 실패) → 시각 모름
#   ./run_demo.sh 2>&1 | tee ../results/16-ota-demo.txt
set -uo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
step() { printf '\n### %s\n' "$*"; }
run()  { printf '$ %s\n' "$*"; "$@"; }

./make_pki.sh --force >/dev/null
rm -rf device out/fw

step "1. 펌웨어 이미지 만들기 (openssl ECDSA P-256 / SHA-256 서명)"
run $PY build_fw.py 1.0.0 --sv 1 --bundle out/r1/root.crt --build-time 2026-03-02T00:00:00Z
run $PY build_fw.py 1.1.0 --sv 2 --bundle out/r1/root.crt out/r2/root.crt --build-time 2026-09-01T00:00:00Z
run $PY build_fw.py 1.2.0 --sv 2 --bundle out/r1/root.crt out/r2/root.crt --build-time 2026-10-01T00:00:00Z --selftest fail
run $PY build_fw.py 1.1.0 --sv 2 --bundle out/r1/root.crt out/r2/root.crt --key out/wrong/wrong.key --name boiler-1.1.0-wrongkey
cp out/fw/boiler-1.1.0.bin out/fw/boiler-1.1.0-tampered.bin
cp out/fw/boiler-1.1.0.manifest.json out/fw/boiler-1.1.0-tampered.manifest.json
printf 'EVIL' | dd of=out/fw/boiler-1.1.0-tampered.bin bs=1 seek=40 conv=notrunc 2>/dev/null
echo "(boiler-1.1.0-tampered.bin: 1.1.0 이미지의 40번째 바이트부터 4바이트를 바꿈. 매니페스트는 원본 그대로)"
run cat out/fw/boiler-1.1.0.manifest.json; echo
run openssl dgst -sha256 -verify out/ota/ota_sign.pub -signature out/fw/boiler-1.1.0.sig.der out/fw/boiler-1.1.0.payload
run openssl dgst -sha256 -verify out/ota/ota_sign.pub -signature out/fw/boiler-1.1.0-wrongkey.sig.der out/fw/boiler-1.1.0-wrongkey.payload

step "2. 공장 출고: 1.0.0 (루트 R1만 들어 있음)"
run $PY device_sim.py factory --dev boiler-01 --fw boiler-1.0.0
run $PY device_sim.py factory --dev boiler-02 --fw boiler-1.0.0

step "3. 서버 두 개 (18470: R1 사슬, 18471: R2 사슬로 옮긴 뒤)"
$PY tls_server.py > out/server.log 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT; sleep 1; cat out/server.log
run $PY device_sim.py connect --dev boiler-01 --port 18470
run $PY device_sim.py connect --dev boiler-01 --port 18471

step "4. OTA 1.1.0 (루트 R1+R2) → 슬롯 B로 전환"
run $PY device_sim.py ota --dev boiler-01 --fw boiler-1.1.0
run $PY device_sim.py connect --dev boiler-01 --port 18471
run $PY device_sim.py connect --dev boiler-01 --port 18470
echo "(boiler-02는 OTA를 못 받은 기기)"
run $PY device_sim.py connect --dev boiler-02 --port 18471

step "5. 위조 이미지 두 가지"
run $PY device_sim.py ota --dev boiler-01 --fw boiler-1.1.0-tampered
run $PY device_sim.py ota --dev boiler-01 --fw boiler-1.1.0-wrongkey

step "6. 롤백: 정상 서명된 옛 1.0.0 (sv 1)"
run $PY device_sim.py ota --dev boiler-01 --fw boiler-1.0.0

step "7. 자체 시험에 실패하는 1.2.0 → A/B 되돌리기"
run $PY device_sim.py ota --dev boiler-01 --fw boiler-1.2.0

step "8. RTC 없는 기기: 시각 1970, 빌드 시각 하한 2026-09-01"
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/chain.pem --clock 1970 --policy naive
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/chain.pem --clock 1970 --policy floor
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/chain.pem --clock 1970 --policy unsynced
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/expired-chain.pem --clock 1970 --policy unsynced
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "(시각 동기화 뒤: $NOW)"
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/chain.pem --clock "$NOW" --policy naive
run $PY device_sim.py checktime --dev boiler-01 --chain out/r2/expired-chain.pem --clock "$NOW" --policy naive

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
echo; echo "서버 종료"

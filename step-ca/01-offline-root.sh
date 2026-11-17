#!/usr/bin/env bash
# 11·12편 ①: 루트는 "오프라인 PC"에서 만든다. 여기서는 네트워크가 없는 컨테이너(--network none)로 흉내 낸다.
# 루트 키는 out/offline/ 에만 남는다. 실무라면 이 폴더는 USB·금고·HSM으로 가고, 온라인 서버에는 root.crt만 간다.
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
mkdir -p out/offline out/online
if [[ -f out/offline/root.crt ]]; then echo "이미 있음: out/offline (다시: ./down.sh --purge)"; exit 0; fi
echo "fake-lab-password-only" > out/offline/root-pass.txt   # 실습용. 실무 비밀번호는 파일에 두지 않는다
chmod 600 out/offline/root-pass.txt
echo "== 루트 만들기 (network none)"
step_cli --network none $STEP_CLI step certificate create "Lab Corp Offline Root R1" \
  offline/root.crt offline/root.key --profile root-ca --kty EC --curve P-256 \
  --not-after 87600h --password-file offline/root-pass.txt
echo "== 온라인 중간 CA 만들기 (이름 제약: lab.example 아래만)"
echo "fake-lab-password-only" > out/online/inter-pass.txt; chmod 600 out/online/inter-pass.txt
step_cli --network none -v "$PWD/templates:/tpl:ro" $STEP_CLI step certificate create "Lab Corp Online Issuing CA I1" \
  online/inter.crt online/inter.key --template /tpl/intermediate-nc.tpl \
  --ca offline/root.crt --ca-key offline/root.key --ca-password-file offline/root-pass.txt \
  --kty EC --curve P-256 --not-after 8760h --password-file online/inter-pass.txt
cp out/offline/root.crt out/online/root.crt   # 온라인 쪽에는 루트 "인증서"만 복사한다
echo "== 확인"
openssl x509 -in out/online/inter.crt -noout -subject -issuer -dates -ext basicConstraints,nameConstraints
openssl verify -CAfile out/online/root.crt out/online/inter.crt
echo "== 온라인 쪽에 있는 파일(루트 키 없음)"; ls -1 out/online

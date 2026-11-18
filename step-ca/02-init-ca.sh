#!/usr/bin/env bash
# 수업 5-1·5-2 ②: 온라인 서버에 step-ca를 차린다. 루트 키 없이 root.crt + 중간 CA만 쓴다.
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
[[ -f out/online/inter.crt ]] || ./01-offline-root.sh
if [[ -f out/stepca/config/ca.json ]]; then echo "이미 있음: out/stepca"; exit 0; fi
mkdir -p out/stepca/secrets
cp out/online/inter-pass.txt out/stepca/secrets/password
cp out/online/inter-pass.txt out/stepca/secrets/prov-password
run() { docker run --rm -v "$PWD/out/stepca:/home/step" -v "$PWD/out/online:/home/step/online" -e STEPPATH=/home/step $STEP_CLI "$@"; }
# init은 자기 루트·중간을 새로 만든다. 그것들은 버리고 우리 것으로 바꾼다.
run step ca init --deployment-type standalone --name "Lab Corp CA" \
  --dns ca.lab.example --dns 127.0.0.1 --address :9000 \
  --provisioner admin@lab.example --password-file /home/step/secrets/password \
  --provisioner-password-file /home/step/secrets/prov-password --ssh --acme 2>&1 | perl -pe "s/\e\[[0-9;]*m//g" | sed '/FEEDBACK/,$d' | grep -v '^$'
rm -f out/stepca/secrets/root_ca_key out/stepca/secrets/intermediate_ca_key out/stepca/certs/root_ca.crt out/stepca/certs/intermediate_ca.crt
../.venv/bin/python patch_ca_json.py out/stepca/config/ca.json
cp out/online/root.crt out/stepca/certs/root_ca.crt   # step CLI가 기본으로 찾는 루트 경로
# defaults.json의 지문을 우리 루트로
FP=$(openssl x509 -in out/online/root.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)
sed -i '' "s/\"fingerprint\": \"[0-9a-f]*\"/\"fingerprint\": \"$FP\"/" out/stepca/config/defaults.json
echo "== secrets/ (루트 키 없음)"; ls -1 out/stepca/secrets
echo "== 프로비저너"; ../.venv/bin/python -c 'import json;[print(" -",p["type"],p["name"]) for p in json.load(open("out/stepca/config/ca.json"))["authority"]["provisioners"]]'

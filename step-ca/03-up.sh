#!/usr/bin/env bash
# step-ca를 127.0.0.1:18430 에 띄운다. 컨테이너끼리는 ca.lab.example:9000 으로 부른다.
set -euo pipefail
cd "$(dirname "$0")"; source env.sh
[[ -f out/stepca/config/ca.json ]] || ./02-init-ca.sh
docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
docker run -d --name pki-lab-step-ca --network $NET --network-alias ca.lab.example \
  -v "$PWD/out/stepca:/home/step" -v "$PWD/out/online:/home/step/online:ro" \
  -p 127.0.0.1:18430:9000 $STEP_CA >/dev/null
for i in $(seq 1 30); do curl -sf --cacert out/online/root.crt https://127.0.0.1:18430/health && break; sleep 1; done; echo
docker logs pki-lab-step-ca 2>&1 | grep -vE '^\s*$' | tail -8

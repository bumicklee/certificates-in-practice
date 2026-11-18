#!/usr/bin/env bash
# 수업 9-5 실습: 서버를 띄우고 demo.py를 돌린 뒤 서버를 끈다.
set -euo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
$PY server.py & SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:18490/docs && break; sleep 0.2; done
$PY demo.py

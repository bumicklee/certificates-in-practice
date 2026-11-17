#!/usr/bin/env bash
# 30편 실습: 파일 만들기 → 두 서버 띄우기 → 점검 → 서버 끄기
set -euo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
./make_files.sh >/dev/null
$PY server.py site 18492 & A=$!
$PY server.py site-broken 18493 & B=$!
trap 'kill $A $B 2>/dev/null || true' EXIT
sleep 1
echo "== 올바른 세트 =="
$PY check.py https://localhost:18492 --cert keys/app-signing.crt --package example.lab.shop || true
echo; echo "== 틀린 세트 =="
$PY check.py https://localhost:18493 --cert keys/app-signing.crt --package example.lab.shop || true

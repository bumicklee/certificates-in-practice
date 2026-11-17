#!/usr/bin/env bash
# 30편 실습: .well-known 파일 세트를 만든다.
#   site/            올바른 세트
#   site-broken/     일부러 틀린 세트(지문 다름, security.txt 만료, JWKS에 개인키 값, 잘못된 Content-Type)
#   keys/            가짜 앱 서명 인증서 2개(앱용·디버그용), JWT 서명 키 (실습 전용, 문서에 붙이지 않는다)
set -euo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
mkdir -p keys site/.well-known site-broken/.well-known
k() { [[ -f "keys/$1.key" ]] || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "keys/$1.key" 2>/dev/null; chmod 600 "keys/$1.key"; }
k app-signing; k debug-signing; k jwt-signing
# Play 앱 서명 키를 흉내 낸 자체 서명 인증서(진짜 Android 서명 인증서도 보통 자체 서명이다)
[[ -f keys/app-signing.crt ]] || openssl req -x509 -new -key keys/app-signing.key -sha256 -days 9125 \
  -subj "/O=FAKE Shop Lab/CN=FAKE Shop Android App Signing" -out keys/app-signing.crt
[[ -f keys/debug-signing.crt ]] || openssl req -x509 -new -key keys/debug-signing.key -sha256 -days 365 \
  -subj "/O=Android/CN=Android Debug (FAKE)" -out keys/debug-signing.crt
$PY gen_json.py
echo "만듦: site/.well-known, site-broken/.well-known"

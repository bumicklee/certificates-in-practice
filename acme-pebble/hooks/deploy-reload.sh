#!/bin/sh
# lego --deploy-hook: 새 인증서가 실제로 발급됐을 때만 불린다.
# 인증서 파일을 바꾼 뒤 nginx에 "다시 읽어라"만 보낸다(연결을 끊지 않는 reload).
set -e
echo "[deploy-hook] $(date -u +%FT%TZ) domains=${LEGO_HOOK_CERT_DOMAINS:-?} cert=${LEGO_HOOK_CERT_PATH:-?}"
nginx -t 2>&1 | tail -1
nginx -s reload
echo "[deploy-hook] nginx reloaded"

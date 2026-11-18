#!/bin/sh
# lego exec DNS 공급자용 훅. lego가 "present|cleanup <fqdn> <value>"로 부른다.
# 실서비스라면 여기서 DNS 공급자 API를 부른다. 이 API 토큰이 수업 4-1·4-2 피해 범위의 주인공이다.
set -e
action="$1"; fqdn="$2"; value="$3"
case "$action" in
  present) wget -q -O- --post-data "{\"host\":\"$fqdn\",\"value\":\"$value\"}" http://challtestsrv:8055/set-txt ;;
  cleanup) wget -q -O- --post-data "{\"host\":\"$fqdn\"}" http://challtestsrv:8055/clear-txt ;;
  *) exit 0 ;;
esac
echo "[hook] $action TXT $fqdn"

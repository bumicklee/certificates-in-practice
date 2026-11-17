#!/usr/bin/env bash
# 1) 예비(백업) 중간 CA 키를 만들어 공개키만 꺼내 둔다(실무에서는 오프라인 금고에 보관하는 키)
# 2) 지금 중간 CA 핀 + 예비 핀으로 network_security_config.xml 을 만든다
set -euo pipefail
cd "$(dirname "$0")"
CA=../private-ca/out
mkdir -p out res/xml res/raw
if [[ ! -f out/backup-inter.key ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out out/backup-inter.key 2>/dev/null; chmod 600 out/backup-inter.key
fi
openssl pkey -in out/backup-inter.key -pubout -out out/backup-inter.pub
cp $CA/root.crt res/raw/lab_root.pem
PY=../.venv/bin/python
PIN_INTER=$($PY compute_pins.py $CA/inter.crt | tail -1 | sed 's#.*sha256/##')
PIN_BACKUP=$($PY compute_pins.py out/backup-inter.pub | tail -1 | sed 's#.*sha256/##')
sed -e "s#@PIN_INTER@#$PIN_INTER#" -e "s#@PIN_BACKUP@#$PIN_BACKUP#" network_security_config.template.xml > res/xml/network_security_config.xml
echo "만듦: res/xml/network_security_config.xml (지금 핀 $PIN_INTER, 예비 핀 $PIN_BACKUP)"

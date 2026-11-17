#!/usr/bin/env bash
cd "$(dirname "$0")"; source env.sh
docker rm -f pki-lab-acme-web pki-lab-acme-pebble pki-lab-acme-dns >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
echo "정리 끝"

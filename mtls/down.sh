#!/usr/bin/env bash
cd "$(dirname "$0")"; source env.sh
docker rm -f pki-lab-mtls-nginx pki-lab-mtls-backend-vuln pki-lab-mtls-backend-safe pki-lab-mtls-pg pki-lab-mtls-attacker >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
echo "정리 끝"

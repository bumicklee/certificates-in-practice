#!/usr/bin/env bash
# 컨테이너와 네트워크를 지운다. --purge 를 주면 out/ (루트·중간 CA·발급물)도 지운다.
cd "$(dirname "$0")"; source env.sh
docker rm -f pki-lab-step-ca pki-lab-step-sshd >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
[[ "${1:-}" == "--purge" ]] && rm -rf out sshd/user_ca.pub && echo "out/ 지움"
echo "정리 끝"

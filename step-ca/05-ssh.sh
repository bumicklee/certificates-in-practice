#!/usr/bin/env bash
# 11·12편 ④: SSH 사용자 인증서 — 발급, ssh-keygen -L, sshd(TrustedUserCAKeys)로 로그인
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
mkdir -p out/ssh; rm -f out/ssh/id_ecdsa*
CLI() { docker run --rm --network $NET -v "$PWD/out:/work" -w /work $STEP_CLI "$@" 2>&1 | perl -pe "s/\e\[[0-9;]*m//g"; }

echo "== 1) 사용자 인증서 발급: alice@lab.example (기본 4h)"
CLI step ssh certificate alice@lab.example ssh/id_ecdsa --no-password --insecure --no-agent \
  --ca-url https://ca.lab.example:9000 --root online/root.crt \
  --provisioner admin@lab.example --provisioner-password-file stepca/secrets/prov-password
chmod 600 out/ssh/id_ecdsa
echo; echo "== 2) ssh-keygen -L"
ssh-keygen -L -f out/ssh/id_ecdsa-cert.pub

echo; echo "== 3) sshd 컨테이너 (127.0.0.1:18432)"
cp out/stepca/certs/ssh_user_ca_key.pub sshd/user_ca.pub
docker image inspect alpine:3.24.3 >/dev/null 2>&1 || docker pull -q alpine:3.24.3 >/dev/null
docker build -q -t pki-lab-sshd:alpine3.24.3 sshd >/dev/null
docker rm -f pki-lab-step-sshd >/dev/null 2>&1
docker run -d --name pki-lab-step-sshd -p 127.0.0.1:18432:22 \
  -v "$PWD/sshd/user_ca.pub:/etc/ssh/user_ca.pub:ro" pki-lab-sshd:alpine3.24.3 >/dev/null
sleep 2
grep -E '^(TrustedUserCAKeys|AuthorizedKeysFile|PasswordAuthentication)' sshd/sshd_config
SSH="ssh -F /dev/null -p 18432 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o IdentitiesOnly=yes"

echo; echo "== 4) 인증서로 alice 로그인"
$SSH -i out/ssh/id_ecdsa -o CertificateFile=out/ssh/id_ecdsa-cert.pub alice@127.0.0.1 'echo "logged in as $(whoami) on $(hostname)"'; echo "exit=$?"
echo; echo "== 5) 같은 키, 인증서 없이"
$SSH -i out/ssh/id_ecdsa -o CertificateFile=/dev/null alice@127.0.0.1 true; echo "exit=$?"
echo; echo "== 6) alice 인증서로 bob 계정에"
$SSH -i out/ssh/id_ecdsa -o CertificateFile=out/ssh/id_ecdsa-cert.pub bob@127.0.0.1 true; echo "exit=$?"
echo; echo "== 7) sshd 로그"
docker logs pki-lab-step-sshd 2>&1 | grep -E 'Accepted|cert|principal|Failed|not listed|Authentication refused' | sed 's/port [0-9]*/port <매번 다름>/'

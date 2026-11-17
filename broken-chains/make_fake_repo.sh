#!/usr/bin/env bash
# 비밀값 검사 연습용 가짜 저장소를 out/fake-repo 에 만든다.
# 안에 든 키는 이 스크립트가 방금 만든 버리는 키이고, 어디에도 쓰이지 않는다.
#   커밋 1: 서버 키와 키가 섞인 PEM 묶음, 가짜 토큰을 커밋 (실수)
#   커밋 2: server.key 를 지움 ("지웠으니 괜찮다"고 착각하는 상황)
set -euo pipefail
cd "$(dirname "$0")"
R=out/fake-repo
rm -rf "$R"; mkdir -p "$R"/{deploy,tls,config,docs}
cd "$R"
git init -q -b main
git config user.name "lab"; git config user.email "lab@lab.example"; git config commit.gpgsign false

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out deploy/server.key 2>/dev/null
openssl req -x509 -new -key deploy/server.key -subj "/CN=fake.lab.example" -days 1 -out tls/fake.crt 2>/dev/null
cat tls/fake.crt deploy/server.key > tls/bundle.pem           # 인증서와 키를 한 파일에 (흔한 실수)
cp tls/fake.crt docs/example-cert.pem                          # 인증서(공개)는 비밀이 아니다 → 걸리면 안 됨
printf 'APP_ENV=dev\nDB_PASSWORD=FAKE-not-a-real-password\nAPI_TOKEN=FAKE-0000-0000-0000\n' > config/app.env
printf '# fake service\n' > README.md
git add -A; git commit -q -m "first deploy"

git rm -q deploy/server.key
git commit -q -m "remove key"
echo "만듦: $(pwd)"
git log --oneline

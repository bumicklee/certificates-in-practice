#!/usr/bin/env bash
# 수업 6-2·6-3 곁가지: PostgreSQL sslmode. require는 "암호화만", verify-full이어야 "누구와"까지 확인한다.
set -uo pipefail
cd "$(dirname "$0")"; source env.sh
export PGPASSWORD=fake-lab-password-only   # 실습용 가짜 비밀번호
ROOT=../private-ca/out/root.crt
start_pg() {  # start_pg <cert> <key>
  docker rm -f pki-lab-mtls-pg >/dev/null 2>&1
  docker run -d --name pki-lab-mtls-pg -e POSTGRES_PASSWORD=$PGPASSWORD \
    -v "$1:/in/server.crt:ro" -v "$2:/in/server.key:ro" -p 127.0.0.1:18445:5432 \
    --entrypoint sh $PG_IMG -c 'mkdir -p /ssl && cp /in/* /ssl/ && chown postgres /ssl/* && chmod 600 /ssl/server.key &&
      exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/ssl/server.crt -c ssl_key_file=/ssl/server.key' >/dev/null
  for i in $(seq 1 30); do pg_isready -q -h 127.0.0.1 -p 18445 && break; sleep 1; done; sleep 2
}
q() { echo "\$ psql \"$1\""; psql "$1 user=postgres dbname=postgres connect_timeout=5" -Atc \
  "select 'connected, ssl='||ssl||', '||version from pg_stat_ssl where pid=pg_backend_pid()" 2>&1 | sed 's/^/  /'; }

echo "== A) 서버 인증서: 자체 서명 CN=wrong.example (아무도 믿지 않는 인증서)"
start_pg "$PWD/out/pg/server.crt" "$PWD/out/pg/server.key"
q "host=127.0.0.1 port=18445 sslmode=require"
q "host=127.0.0.1 port=18445 sslmode=verify-ca sslrootcert=$ROOT"
q "host=127.0.0.1 port=18445 sslmode=verify-full sslrootcert=$ROOT"

echo; echo "== B) 서버 인증서: 사내 CA 리프 (SAN shop.lab.example, localhost, 127.0.0.1)"
start_pg "$PCA/chain.pem" "$PCA/leaf.key"
q "host=localhost port=18445 sslmode=verify-full sslrootcert=$ROOT"
q "host=db.lab.example hostaddr=127.0.0.1 port=18445 sslmode=verify-full sslrootcert=$ROOT"
q "host=db.lab.example hostaddr=127.0.0.1 port=18445 sslmode=verify-ca sslrootcert=$ROOT"
docker rm -f pki-lab-mtls-pg >/dev/null

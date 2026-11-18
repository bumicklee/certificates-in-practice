# lab/tls13 — TLS 1.3 관찰 (수업 2-2·3-1)

무엇: 공용 사설 사슬(`lab/private-ca/out`)로 127.0.0.1:18400에 `openssl s_server`를 띄우고, `curl -v`·`s_client -msg/-trace`로 핸드셰이크를 본다. 그룹(X25519, P-256, X25519MLKEM768)별 key_share 크기를 비교하고, 연결마다 임시 키가 바뀌는지(PFS) 확인한다.

준비물: OpenSSL 3.5 이상(하이브리드 그룹 `X25519MLKEM768`). 강의는 3.6.3으로 쟀다. `openssl list -kem-algorithms`에 `X25519MLKEM768`이 보여야 한다. 먼저 `../private-ca/make_chain.sh`.

```bash
cd lab/tls13
./server.sh start                       # 127.0.0.1:18400, leaf + inter를 보낸다
curl -v --cacert ../private-ca/out/ca-bundle.pem https://localhost:18400/ -o /dev/null
openssl s_client -connect 127.0.0.1:18400 -servername shop.lab.example \
  -CAfile ../private-ca/out/ca-bundle.pem -msg </dev/null | grep -E '^(<<<|>>>)'
./compare_groups.sh                     # 그룹별 key_share 크기·협상 결과
./pfs_check.sh                          # 세 번 접속, 서버 임시 공개키 비교
../.venv/bin/python peek_relay.py       # 127.0.0.1:18402 중계, 중간에서 보이는 바이트 요약(수업 2-2·3-1)
#   다른 창: curl --cacert ../private-ca/out/ca-bundle.pem -X POST -d 'card=FAKE-4111-0000' https://localhost:18402/login
./server.sh stop
```

- `peek_relay.py`는 내 PC의 내 연결만 중계한다. 한 연결을 넘기고 끝난다.
- 평문 HTTP 비교는 `nc -l 127.0.0.1 18401`로 받은 바이트를 그대로 본다.

정리: `./server.sh stop` (남은 프로세스 확인: `pgrep -fl "s_server -accept 127.0.0.1:184"`)

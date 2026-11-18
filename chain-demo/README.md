# lab/chain-demo — 교차 서명·중간 누락·CA:TRUE 리프 (수업 3-2·7-1)

무엇: 공용 사슬(`lab/private-ca/out`)은 **읽기만** 하고, 시연용 사슬은 이 폴더의 `out/`에 따로 만든다.

| 파일 | 하는 일 |
|---|---|
| `make_demo.sh` | 옛 루트 X1·새 루트 Y1, 두 루트가 각각 서명한 같은 키의 중간 CA C1, 리프 `api.lab.example`, 새 루트를 옛 루트가 교차 서명한 `rootY-by-X.crt`, AIA·CRL 배포 지점이 든 리프, `CA:TRUE`가 잘못 들어간 리프와 그 리프가 찍어 낸 `bank.lab.example` |
| `verify_demo.sh` | 중간 누락, 두 루트 경로, 중간 인증서 순서에 따른 경로 선택, 루트 교차 서명 사슬을 `openssl verify`로 검사 |
| `ca_true_demo.sh` | `CA:TRUE` 리프가 남의 이름을 찍어 낼 때 pathlen 제한·CA:FALSE가 어떻게 막는지 |
| `verify_by_hand.py` | cryptography로 사슬의 서명·기간을 한 단계씩 확인. 1바이트 변조·중간 건너뛰기 실패 |

```bash
cd lab/chain-demo
./make_demo.sh
./verify_demo.sh
./ca_true_demo.sh
../.venv/bin/python verify_by_hand.py
```

서버가 중간 인증서를 빠뜨리는 경우(수업 3-2):

```bash
openssl s_server -accept 127.0.0.1:18403 -cert ../private-ca/out/leaf.crt -key ../private-ca/out/leaf.key -www &
openssl s_client -connect 127.0.0.1:18403 -servername shop.lab.example -CAfile ../private-ca/out/ca-bundle.pem </dev/null | grep Verify
kill %1
```

정리: `rm -rf lab/chain-demo/out`

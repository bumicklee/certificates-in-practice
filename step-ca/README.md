# lab/step-ca — 사내 CA(step-ca): 오프라인 루트, 짧은 수명 인증서, 이름 제약, SSH 사용자 인증서

수업 5-1·5-2 실습 폴더입니다. 수업 9-1(IoT 프로비저닝)도 이 폴더의 CA를 **읽기 전용으로** 다시 씁니다.

## 무엇을 하나

| 스크립트 | 하는 일 | 결과 원문 |
|---|---|---|
| `01-offline-root.sh` | 네트워크 없는 컨테이너(`--network none`)에서 루트(P-256, 10년)를 만들고, 이름 제약(`lab.example`, `127.0.0.0/8`, `10.0.0.0/8`)을 넣은 중간 CA(1년)를 서명 | `../results/08-offline-root.txt` |
| `02-init-ca.sh` | `step ca init --ssh --acme` 후, init이 만든 루트·중간을 버리고 위의 중간 CA로 바꿈. 기본 수명 TLS 24h(최대 72h), SSH 사용자 4h(최대 8h) | `../results/08-init-ca.txt` |
| `03-up.sh` | step-ca를 `127.0.0.1:18430`에 띄움(컨테이너끼리는 `ca.lab.example:9000`) | |
| `04-issue.sh` | `step ca certificate`(JWK 토큰), 이름 제약 밖 요청 거절, `step ca renew`(가진 인증서로 갱신), ACME(lego, HTTP-01) | `../results/08-issue.txt` |
| `05-ssh.sh` | `step ssh certificate`로 사용자 인증서 → `ssh-keygen -L` → `TrustedUserCAKeys`만 둔 sshd(`127.0.0.1:18432`)에 로그인 | `../results/08-ssh.txt` |
| `down.sh` | 컨테이너·네트워크 정리(`--purge`면 `out/`까지) | |

## 준비물

- Docker. 이미지(태그 고정): `smallstep/step-ca:0.30.2`, `smallstep/step-cli:0.31.0`, `goacme/lego:v5.5.2`, `alpine:3.24.3`
- 호스트에 `openssl`, `ssh`/`ssh-keygen`, `../.venv/bin/python`(ca.json 수정용)

## 명령

```bash
cd lab/step-ca
./01-offline-root.sh
./02-init-ca.sh
./03-up.sh
./04-issue.sh
./05-ssh.sh
./down.sh            # 컨테이너만 정리 (CA는 out/에 남음)
./down.sh --purge    # CA까지 지움
```

## 만들어지는 것 (out/)

| 경로 | 무엇 | 비고 |
|---|---|---|
| `out/offline/root.crt`, `root.key` | 오프라인 루트 | **실무라면 이 폴더는 온라인 서버에 없어야 한다.** 실습이라 같은 디스크에 있다 |
| `out/online/root.crt`, `inter.crt`, `inter.key` | 온라인 쪽 파일. 루트는 인증서만 | step-ca가 쓰는 것 |
| `out/stepca/` | step-ca 설정(`config/ca.json`), DB, SSH CA 키 | `certs/ssh_user_ca_key.pub`가 sshd의 `TrustedUserCAKeys` |
| `out/issued/`, `out/lego/`, `out/ssh/` | 발급 결과 | |

비밀번호 파일(`*-pass.txt`, `secrets/password`)에는 `fake-lab-password-only`가 들어 있습니다. 실습용입니다.

## 수업 9-1에서 다시 쓸 때

- `03-up.sh`로 CA만 띄우고, 루트는 `out/online/root.crt`, CA 주소는 컨테이너 안에서 `https://ca.lab.example:9000`(네트워크 `pki-lab-step`), 호스트에서 `https://127.0.0.1:18430`입니다.
- 프로비저너: `admin@lab.example`(JWK, 비밀번호 `out/stepca/secrets/prov-password`), `acme`(ACME), `sshpop`.
- 중간 CA에 이름 제약이 있어서 `lab.example` 아래 DNS·URI, `127.0.0.0/8`·`10.0.0.0/8` IP만 발급됩니다.
- 이 폴더의 스크립트와 `out/`은 고치지 말고, 필요한 설정은 자기 폴더에 두세요.

## 정리

```bash
./down.sh --purge
docker ps --filter name=pki-lab-step   # 비어 있어야 한다
```

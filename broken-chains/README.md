# broken-chains: 일부러 깨뜨린 사슬 다섯 가지와 비밀값 검사 (5·17편)

## 무엇
- `make_broken.sh` — 정상 3단 사슬(`../private-ca/make_chain.sh`를 `OUT=out/base`로 불러 만든다. `lab/private-ca`는 건드리지 않는다) 위에 깨진 사슬을 만든다.
  1. 만료된 리프 · 2. 잘못된 발급자(믿지 않는 다른 CA) · 3. SAN 불일치 · 4. 중간 인증서 누락 · 5. `CA:TRUE`가 잘못 들어간 리프가 `evil.lab.example`을 서명
  - 덤 5b: pathlen·keyUsage 제한이 없는 "허술한 CA"에서 5번과 같은 일을 하면 **검증이 통과한다**. 제한이 왜 필요한지 보여 주는 대조군이다.
- `verify.sh` — `openssl verify`로 하나씩 검증한다.
- `verify.py` — Python 두 검증기: `cryptography.x509.verification`과 `ssl` 모듈의 실제 TLS 핸드셰이크(메모리 안에서, 포트를 열지 않는다).
- `make_fake_repo.sh` + `secret_scan.py` — 가짜 저장소(`out/fake-repo`)에 버리는 키를 커밋했다 지운 뒤, 작업 트리와 git 이력에서 개인키 흔적을 찾는다. **내용은 출력하지 않고 파일·줄·커밋만** 보인다.

## 준비물
- OpenSSL 3.x(`-not_before`/`-not_after` 옵션이 필요하다. 3.4 이상), git
- `lab/.venv` (cryptography 42 이상)

## 명령 (`lab/broken-chains/`에서)
```bash
./make_broken.sh            # 다시 만들려면 --force
./verify.sh
../.venv/bin/python verify.py
./make_fake_repo.sh
../.venv/bin/python secret_scan.py out/fake-repo   # 찾으면 종료 코드 1
```
결과 파일(직접 돌리면 생김): `../results/11-openssl-verify.txt`, `../results/11-python-verify.txt`, `../results/11-secret-scan.txt`

## 정리
```bash
rm -rf out
```
서버·컨테이너는 띄우지 않는다.

## 안전
- 모든 이름은 `*.lab.example`, 키는 이 폴더에서 방금 만든 버리는 키다. 문서·화면에 키 내용을 붙이지 않는다.
- 이 폴더는 "검증기가 무엇을 거부하는지"를 보는 곳이다. 깨진 인증서로 다른 시스템을 속이는 용도로 쓰지 않는다.

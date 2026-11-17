# mobile-pins: Network Security Config와 SPKI 핀 계산 (19편)

## 무엇
- `network_security_config.template.xml` — Android Network Security Config 예제 틀
  - `base-config`: 평문 금지, 시스템 CA만 신뢰
  - `domain-config`(api.lab.example): 사설 루트만 신뢰 + `pin-set`(지금 중간 CA 핀 + 예비 핀, `expiration`)
  - `debug-overrides`: 디버그 빌드에서만 사설 루트를 더 신뢰
- `make_backup_and_config.sh` — 예비 중간 CA 키를 만들고(`out/backup-inter.key`, 공개키만 핀에 쓴다) 실제 핀 값을 넣은 `res/xml/network_security_config.xml`을 만든다.
- `compute_pins.py` — 인증서·공개키 파일에서 `base64(SHA-256(SPKI DER))` 핀을 계산한다. openssl 파이프라인과 같은 값이 나온다.
- `make_rotations.sh` + `pin_check.py` — 중간 CA를 ①예비 키로 바꾼 경우 ②핀에 없는 키로 바꾼 경우를 만들고, pin-set 규칙(사슬 안에 고정한 키가 하나라도 있으면 통과, 만료일 뒤에는 피닝 끔)으로 판정한다. **학습용 흉내**이고 Android 구현이 아니다.

## 준비물
- `../private-ca/out/`(없으면 `../private-ca/make_chain.sh`). root·inter 키는 **읽기만** 한다(새 중간 CA 서명에 씀).
- `lab/.venv`(cryptography)

## 명령 (`lab/mobile-pins/`에서)
```bash
./make_backup_and_config.sh
../.venv/bin/python compute_pins.py ../private-ca/out/root.crt ../private-ca/out/inter.crt ../private-ca/out/leaf.crt out/backup-inter.pub
openssl x509 -in ../private-ca/out/inter.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64
./make_rotations.sh
../.venv/bin/python pin_check.py res/xml/network_security_config.xml out/current/chain.pem
../.venv/bin/python pin_check.py res/xml/network_security_config.xml out/rot-backup/chain.pem
../.venv/bin/python pin_check.py res/xml/network_security_config.xml out/rot-unknown/chain.pem
../.venv/bin/python pin_check.py res/xml/network_security_config.xml out/rot-unknown/chain.pem 2027-05-01
```
결과 파일(직접 돌리면 생김): `../results/14-pins.txt`, `../results/14-pin-check.txt`

`../private-ca/make_chain.sh --force`로 공용 CA를 다시 만들면 핀 값이 바뀐다. 그때는 `./make_backup_and_config.sh`를 다시 돌린다.

## 정리
```bash
rm -rf out res
```

## 안전 범위
클라이언트 쪽 검증(피닝 포함)은 기기를 가진 사람이 우회할 수 있다는 **사실**만 다룬다. 우회 방법·후킹 스크립트·시스템 CA 주입 절차는 다루지 않는다. 대책은 서버 쪽 증명(27편)이다.

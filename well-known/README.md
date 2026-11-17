# well-known (30편)

`.well-known` 파일 세트(assetlinks.json, apple-app-site-association, openid-configuration, jwks.json, security.txt, change-password, webauthn)와 점검 스크립트.

- `make_files.sh` 가짜 앱 서명 인증서 2장(배포·디버그)과 JWT 키를 `keys/`에 만들고, `site/`(올바름)·`site-broken/`(틀림) 세트를 만든다
- `server.py` 세트를 HTTPS로 서비스(공용 사설 CA 리프 사용). `site` 127.0.0.1:18492, `site-broken` 127.0.0.1:18493
- `check.py` Content-Type, JSON 모양, 지문 일치, JWKS 개인키 필드, issuer, security.txt Expires·Canonical, 리다이렉트 점검

## 준비물
`lab/.venv`, `../private-ca/out/`(없으면 `../private-ca/make_chain.sh`)

## 실행
```bash
./run.sh     # 파일 생성 → 서버 둘 → 점검 두 번 → 서버 종료. 결과: ../results/20-well-known-check.txt
openssl x509 -in keys/app-signing.crt -noout -fingerprint -sha256   # assetlinks에 넣는 지문
```

## 정리
```bash
rm -rf keys site site-broken
```
`keys/`의 키는 실습 전용이다. 문서나 저장소에 올리지 않는다(`.gitignore`).

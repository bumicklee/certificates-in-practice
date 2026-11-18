# webauthn (수업 9-5)

localhost WebAuthn 등록·로그인과 "출처 묶기" 확인. 브라우저 대신 Python 소프트웨어 인증기(ES256, `none` 증명)가 진짜 형식의 응답을 만든다.

- `server.py` FastAPI + py_webauthn. RP ID `localhost`, 허용 출처 `http://localhost:18490`, 127.0.0.1:18490
- `soft_authenticator.py` 소프트웨어 인증기 + 브라우저 흉내(RP ID 검사, clientDataJSON에 출처 기록)
- `demo.py` 등록·로그인 성공, 피싱 출처(`http://shop-login.lab.example`)에서 브라우저·인증기·서버 거부, 재전송 거부

## 준비물
`lab/.venv` (fastapi, uvicorn, webauthn, httpx, cryptography, cbor2 — cbor2는 webauthn 의존성으로 이미 설치됨)

## 실행
```bash
./run.sh     # 서버를 띄우고 demo.py 실행 후 서버 종료. 결과: ../results/19-webauthn-demo.txt
```

## 정리
`run.sh`가 끝날 때 서버를 끈다. 남아 있으면 `lsof -nP -iTCP:18490 -sTCP:LISTEN`로 PID를 찾아 끈다.

실습 전용 코드다. 소프트웨어 인증기를 실서비스에 쓰지 않는다.

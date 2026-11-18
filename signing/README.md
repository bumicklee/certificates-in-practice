# lab/signing — 전자서명 실습 (수업 3-3)

무엇: ES256 JWT와 JWKS(`kid`) 키 교체, HS256 vs ES256 위조 비교, 작은 API 요청 서명, 로컬 TSA(RFC 3161) 타임스탬프.

준비물: `lab/.venv`(cryptography, pyjwt), OpenSSL 3.x. 네트워크는 127.0.0.1만 쓴다(JWKS 서버 18410).

| 파일 | 하는 일 |
|---|---|
| `jwks_rotation.py` | 127.0.0.1:18410에 JWKS를 띄우고 3단계(옛 키 → 겹침 → 옛 키 퇴역)로 토큰 검증. 변조·`alg=none` 거부도 본다. 스크립트가 끝나면 서버도 꺼진다 |
| `hmac_vs_es256.py` | 검증만 하는 서비스가 HS256에서는 토큰을 위조할 수 있고 ES256에서는 못 하는 것을 본다 |
| `request_signing.py` | 메서드·경로·시각·nonce·본문 해시 서명. 재전송·변조·오래된 서명 거부 |
| `tsa_demo.sh` | `out/`에 서명자·TSA 사슬을 만들고, CMS 서명 → `ts -query` → `ts -reply` → `ts -verify`. `-attime`으로 "서명자 인증서 만료 뒤" 검증을 재현 |

```bash
cd lab/signing
../.venv/bin/python jwks_rotation.py
../.venv/bin/python hmac_vs_es256.py
../.venv/bin/python request_signing.py
./tsa_demo.sh
```

- TSA 인증서는 EKU `timeStamping`을 critical로 넣어야 `openssl ts -verify`가 받아 준다.
- 여기서는 서명 파일(`contract.p7s`) 전체에 타임스탬프를 찍었다. 실제 CMS/PAdES는 서명 값에 대한 타임스탬프를 서명 안(서명되지 않은 속성)에 넣는다.
- 실습 키는 `out/` 안에만 있다. 문서나 저장소에 개인키 내용을 붙이지 않는다.

정리:

```bash
rm -rf lab/signing/out
```

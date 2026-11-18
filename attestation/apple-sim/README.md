# apple-sim (수업 9-4)

App Attest **서버 검증**을 기기 없이 봅니다.

1. Apple 문서(Attestation Object Validation Guide)에 실린 **진짜 예제 증명 객체**를 **진짜 Apple App Attestation Root CA**로 검증
2. **가짜 루트**(`FAKE App Attestation Root CA (lab, not Apple)`)와 가짜 기기로 성공·실패 사례
3. assertion: 카운터 증가, 재전송, 변조

## 준비물

`lab/.venv` + `requirements.txt` (cryptography, cbor2)

## 데이터 받기 (읽기만)

```bash
cd lab/attestation/apple-sim
curl -sf -o apple/Apple_App_Attestation_Root_CA.pem        https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
curl -sf -o apple/Apple_Enterprise_Attestation_Root_CA.pem https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem
```

`apple/sample_attestation.b64`, `apple/sample_inputs.json`은 https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide 의 예제 값(팀 ID 1234567890, 번들 com.example.myapp, 챌린지 example_server_challenge)을 옮긴 것입니다.

## 명령

```bash
../../.venv/bin/python -I demo.py | tee ../../results/18-2-appattest-demo.txt
openssl x509 -in apple/Apple_App_Attestation_Root_CA.pem -noout -subject -dates -fingerprint -sha256
```

## 파일

| 파일 | 하는 일 |
|---|---|
| `appattest_verifier.py` | `verify_attestation()` Apple 문서 1~11단계, `verify_assertion()` 1~6단계 |
| `fake_device.py` | 가짜 증명 CA(P-384 루트·중간)와 가짜 기기. 인증서·authData 모양은 Apple 예제를 따름 |
| `demo.py` | A(Apple 예제) · B(가짜 루트 6건) · C(assertion 5건) |

## 진짜와 다른 점

| 이 실습 | 실제 |
|---|---|
| 키가 메모리에 있다 | Secure Enclave 안. 꺼낼 수 없다 |
| 가짜 CA가 credCert를 바로 발급 | Apple 서버가 발급(`attestKey` 호출 때 네트워크) |
| receipt = `FAKE-RECEIPT-…` | PKCS#7, Apple Root CA - G3 사슬. 위험 지표 조회에 쓴다 |
| 확장 `apple_validation_category_01` 값은 검사하지 않음 | 서비스가 기대 값을 정한다 |

실기기 흐름(`DCAppAttestService`로 받은 객체를 이 검증기에 넣기)은 【직접 해 보기: 기기】.

## 정리

가짜 루트는 실행할 때마다 메모리에서 새로 만들고 파일로 남기지 않습니다. 받은 루트를 지우려면 `rm apple/*.pem`.

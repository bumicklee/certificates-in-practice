# attestation (27편)

기기 증명을 **서버(검증하는 쪽)** 입장에서 봅니다. 기기는 없고, 가짜 루트·가짜 기기가 만든 사슬을 검증 코드가 받아 판단합니다. 네트워크도 쓰지 않습니다.

1. **Android식 키 증명**: 옛 루트(RSA)와 새 루트(ECDSA P-384)를 함께 믿는 서버, 챌린지, 보안 수준·부팅 상태, 폐기 목록
2. **Matter식 기기 증명**: PAA → PAI → DAC, 신뢰 PAA는 로컬 "DCL" JSON 파일, VID/PID 일치, 32바이트 nonce에 DAC 키로 서명

더 깊이 보기(하위 폴더)

- `android-real/` (27·28편): 진짜 Android 시험용 증명 사슬 4개 + Google 루트·폐기 목록으로 KeyDescription 파싱과 체크리스트 12줄
- `apple-sim/` (29편): Apple 예제 증명 객체를 진짜 Apple 루트로 검증 + 가짜 루트 App Attest 시뮬레이터

## 준비물

`lab/.venv` (cryptography 40 이상. `verify_directly_issued_by`를 씁니다)

## 명령

```bash
cd lab/attestation
../.venv/bin/python android_demo.py | tee ../results/18-android-attestation.txt
../.venv/bin/python matter_demo.py  | tee ../results/18-matter-attestation.txt
```

## 파일

| 파일 | 하는 일 |
|---|---|
| `fakepki.py` | 가짜 CA·인증서 도우미 |
| `android_verifier.py` | **서버 검증 함수** `verify_attestation()`: 루트 공개키 비교 → 사슬 서명·CA → 폐기 목록 → 챌린지 → 정책 |
| `android_demo.py` | 가짜 루트 두 개, 기기 두 대(옛·새), 실패 사례들 |
| `matter_verifier.py` | **커미셔너 검증 함수** `verify_device()`: DCL에서 PAA → 사슬 → PAI 폐기 → VID/PID → nonce → DAC 서명 |
| `matter_demo.py` | 가짜 PAA(VID FFF1)·PAI(PID 8000)·DAC, DCL 파일 `out/dcl.json` |

## 결과 (2026-10-31 실측)

Android식 (`../results/18-android-attestation.txt`)

| 서버 신뢰 목록 | 기기 | 결과 |
|---|---|---|
| 옛 + 새 | 옛 루트 기기 | PASS |
| 옛 + 새 | 새 루트 기기 | PASS |
| 옛 + 새 | 자체 루트(에뮬레이터) | FAIL untrusted root |
| 옛 + 새 | 새 루트와 이름만 같은 가짜 루트 | FAIL untrusted root (공개키로 비교) |
| 옛 + 새 | 지난 세션의 응답 재사용 | FAIL challenge mismatch |
| 옛 + 새 | 소프트웨어 키 / 잠금 해제된 부트로더 | FAIL (정책) |
| 옛 + 새 | 배치 키가 폐기 목록에 | FAIL revoked |
| 옛만 | 새 루트 기기 | **FAIL** — 새 루트를 안 넣은 서버 |

Matter식 (`../results/18-matter-attestation.txt`): 진품 PASS / DCL에 없는 PAA, VID 불일치, PID 불일치, 옛 nonce, 인증서만 복사한 복제품, PAI 폐기 모두 FAIL.

## 진짜와 다른 점

| 이 실습 | 실제 |
|---|---|
| 증명 확장 OID `1.3.6.1.4.1.32473.1.17`(문서용 PEN), 내용은 JSON | Android: `1.3.6.1.4.1.11129.2.1.17` KeyDescription(ASN.1). 필드 `attestationChallenge`, `attestationSecurityLevel`(Software/TrustedEnvironment/StrongBox), `rootOfTrust.verifiedBootState`·`deviceLocked` |
| 가짜 루트 두 개 | Google 루트 목록 `https://android.googleapis.com/attestation/root` (2026-10-31에 받은 목록: RSA 4096 루트 1개 + "Key Attestation CA1" ECDSA P-384 루트 1개, `../results/18-android-real-roots.txt`) |
| 폐기 목록 = 딕셔너리 | `https://android.googleapis.com/attestation/status` |
| 리프 유효 기간은 검사에서 뺐다 | 서비스가 정책으로 정한다 |
| Matter CD는 JSON, CSA 서명 검증 생략 | CD는 CSA 키로 서명된 문서, TLV 인코딩 |
| Matter VID/PID OID `1.3.6.1.4.1.37244.2.1`/`.2.2`, 시험용 VID FFF1 | 같음 |

진짜 기기에서 받은 사슬로 돌려 보기는 【직접 해 보기: 기기】로 남깁니다(Android `KeyGenParameterSpec.setAttestationChallenge()`로 만든 키의 `getCertificateChain()`을 서버로 보내기).

## 정리

```bash
rm -rf out
```

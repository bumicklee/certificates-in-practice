# android-real (27·28편)

진짜 Android 기기에서 나온 **공개 시험용 키 증명 사슬**을 읽고, 서버 검증 체크리스트 12줄을 돌립니다.
기기 없이 돕니다. 바깥 요청은 공개 자료를 **읽기만** 합니다.

## 준비물

`lab/.venv` + `requirements.txt` (cryptography, cbor2. 둘 다 이미 설치돼 있으면 건너뜀)

```bash
cd lab
.venv/bin/pip install -r attestation/android-real/requirements.txt
```

## 데이터 받기 (읽기만)

받은 파일은 스크립트와 다른 폴더(`data/`, `google/`)에 둡니다.

```bash
cd lab/attestation/android-real
# 1) android/keyattestation 저장소의 시험 데이터 (Apache-2.0, 2026-10-31에 받은 커밋 34652d3)
for f in akita/sdk34/TEE_EC_NONE blueline/sdk28/SB_RSA_NONE caiman/sdk36/TEE_EC_RKP tegu/sdk36/TEE_EC_2026_ROOT; do
  n=$(echo $f | tr / _)
  curl -sf -o data/$n.pem  https://raw.githubusercontent.com/android/keyattestation/main/testdata/$f.pem
  curl -sf -o data/$n.json https://raw.githubusercontent.com/android/keyattestation/main/testdata/$f.json
done
# 2) Google 루트 목록과 폐기 목록
curl -sf -o google/roots.json https://android.googleapis.com/attestation/root
curl -sf -D google/status.headers -o google/status.json https://android.googleapis.com/attestation/status
```

| 파일 | 기기 | 무엇 |
|---|---|---|
| `blueline_sdk28_SB_RSA_NONE` | Pixel 3, Android 9 | 공장 키, StrongBox, RSA |
| `akita_sdk34_TEE_EC_NONE` | Android 14 | RKP, TEE, EC |
| `caiman_sdk36_TEE_EC_RKP` | Pixel 9 Pro, Android 16 | RKP, TEE, 잠긴 기기 |
| `tegu_sdk36_TEE_EC_2026_ROOT` | Pixel 9a(시제품), Android 16 | **새 루트 Key Attestation CA1** |

## 명령

```bash
../../.venv/bin/python -I verify_real.py --fields | tee ../../results/18-1-android-real-verify.txt
../../.venv/bin/python -I show_status.py          | tee ../../results/18-1-android-status.txt
```

## 파일

| 파일 | 하는 일 |
|---|---|
| `keydesc.py` | KeyDescription(OID `1.3.6.1.4.1.11129.2.1.17`) DER 파서. 스키마 v500 태그 표 |
| `verify_real.py` | 체크리스트 12줄. 받은 시각(creationDateTime)과 지금, 두 시점에서 돌린다 |
| `show_status.py` | 폐기 목록의 모양(항목 수, status·reason 분포, 일련번호는 줄여서) |

## 결과 요약 (2026-10-31)

- 네 사슬 모두 사슬 서명·루트 공개키·폐기 목록은 통과
- `caiman`, `tegu`: 받은 시각 기준 **ACCEPT**. 지금 기준은 RKP 인증서 만료로 REJECT(수명 9일·14일)
- `akita`, `blueline`: 시험 기기라 부트로더가 열려 있어(Unverified, locked=False) 정책에서 REJECT. 챌린지도 `b'challenge'` 9바이트
- 폐기 목록: 1,769개 항목, 모두 REVOKED (KEY_COMPROMISE 1,743 · SOFTWARE_FLAW 26)

실서비스에서는 직접 만든 파서 대신 Android 문서가 권하는 https://github.com/android/keyattestation 같은 검증 라이브러리를 쓰세요.
진짜 폰에서 내 앱으로 받은 사슬을 돌려 보기는 【직접 해 보기: 기기】.

## 정리

```bash
rm -f data/*.pem data/*.json google/*.json google/status.headers
```

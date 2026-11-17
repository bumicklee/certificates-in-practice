# embedded-ota (24편)

보일러 컨트롤러를 흉내 낸 기기 시뮬레이터로 **OTA 이미지 서명 검증, 롤백 방지, A/B 슬롯, 루트 묶음 교체, RTC 없는 기기의 시각 처리**를 봅니다. 기기·서명 키·인증서는 모두 가짜이고, 서버는 `127.0.0.1:18470`, `18471`에만 뜹니다.

## 준비물

- OpenSSL 3.x (`-not_before` 옵션이 필요합니다. 3.4 이상)
- `lab/.venv` (cryptography 42 이상. `cryptography.x509.verification`을 씁니다)

## 파일

| 파일 | 하는 일 |
|---|---|
| `make_pki.sh` | OTA 서명 키(P-256), 위조 실험용 다른 키, 옛 사슬(Root R1 → I1 → 서버)과 새 사슬(Root R2 → I2 → 서버), 이미 만료된 리프를 `out/`에 만든다 |
| `build_fw.py` | 가짜 펌웨어 이미지(코드 + 루트 묶음 PEM + 자체 시험 표시)와 매니페스트를 만들고 `openssl dgst -sha256 -sign`으로 서명한다 |
| `device_sim.py` | 기기. 루트 묶음(활성 슬롯 이미지 안), OTA 공개키, 보안 버전 하한, 빌드 시각 하한을 가진다 |
| `tls_server.py` | 18470(R1 사슬)·18471(R2 사슬) TLS 서버 |
| `run_demo.sh` | 아래 시나리오 전체 |

## 명령

```bash
cd lab/embedded-ota
./run_demo.sh 2>&1 | tee ../results/16-ota-demo.txt
```

하나씩 하려면:

```bash
./make_pki.sh
../.venv/bin/python build_fw.py 1.0.0 --sv 1 --bundle out/r1/root.crt --build-time 2026-03-02T00:00:00Z
../.venv/bin/python build_fw.py 1.1.0 --sv 2 --bundle out/r1/root.crt out/r2/root.crt --build-time 2026-09-01T00:00:00Z
openssl dgst -sha256 -verify out/ota/ota_sign.pub -signature out/fw/boiler-1.1.0.sig.der out/fw/boiler-1.1.0.payload

../.venv/bin/python device_sim.py factory --dev boiler-01 --fw boiler-1.0.0
../.venv/bin/python tls_server.py &          # 끝나면 kill %1
../.venv/bin/python device_sim.py connect --dev boiler-01 --port 18471      # FAIL: R2를 모른다
../.venv/bin/python device_sim.py ota --dev boiler-01 --fw boiler-1.1.0     # 슬롯 B, 하한 1 → 2
../.venv/bin/python device_sim.py connect --dev boiler-01 --port 18471      # OK
../.venv/bin/python device_sim.py ota --dev boiler-01 --fw boiler-1.0.0     # REJECT rollback
../.venv/bin/python device_sim.py checktime --dev boiler-01 --chain out/r2/chain.pem --clock 1970 --policy unsynced
```

## 시나리오와 결과 (2026-10-31 실측, `../results/16-ota-demo.txt`)

| # | 시나리오 | 결과 |
|---|---|---|
| 1 | 정상 1.1.0 | 서명·해시·보안 버전 통과 → 슬롯 B 확정, 하한 1 → 2 |
| 2 | 바이트 4개 바꾼 이미지(매니페스트는 원본) | `REJECT sha256` |
| 3 | 다른 키로 서명 | `REJECT signature` |
| 4 | 정상 서명된 옛 1.0.0 | `REJECT rollback: security_version 1 < 기기 하한 2` |
| 5 | 자체 시험 실패 1.2.0 | 슬롯 A에 썼다가 되돌림, B 유지 |
| 6 | R1만 가진 기기 → R2 서버 | `unable to get local issuer certificate` |
| 7 | OTA로 R1+R2를 받은 기기 → R1·R2 서버 | 둘 다 OK |
| 8 | 시각 1970, 그대로 검사(naive) | 리프 "not valid at validation time" |
| 9 | 시각 1970, 빌드 시각으로 검사(floor) | 빌드 뒤에 발급된 리프라 여전히 실패 |
| 10 | 시각 1970, notBefore는 넘기고 빌드 시각 이전 만료만 거부(unsynced) | 현재 리프 OK, 2026-03-01에 만료된 리프 FAIL |

## 시뮬레이터가 실제와 다른 점

- 실제 TLS 스택(mbedTLS)은 핸드셰이크 안에서 유효 기간을 봅니다. Python `ssl`은 검사 시각을 바꿀 수 없어서, 시각 실험(`checktime`)은 같은 사슬을 `cryptography.x509.verification`으로 따로 검증합니다.
- `unsynced` 정책은 "시각 동기화 전 첫 접속" 한 번을 위한 것입니다. 접속하면 바로 SNTP(또는 서버 응답의 시각)로 시각을 맞추고 정상 검사로 돌아가야 합니다. 이 정책으로는 아직 만료되지 않은 것처럼 보이는 옛 인증서(빌드 시각 이후 만료)를 거르지 못합니다.
- 보안 부팅은 "재부팅할 때 슬롯 해시를 다시 본다"로만 흉내 냅니다. 실제는 ROM 부트로더가 eFuse의 공개키 다이제스트로 부트로더·앱 서명을 검증합니다.

## ESP32에서 같은 일을 하는 설정 【직접 해 보기: 기기】

기기 결과는 아직 재지 않았습니다. 설정 이름과 동작은 ESP-IDF v6.1 문서 기준입니다.

| 이 실습 | ESP-IDF |
|---|---|
| 이미지 안의 루트 묶음 | `esp_crt_bundle` (Mozilla NSS 루트로 생성, 전체 130개 이상 / 자주 쓰는 약 38개 필터 목록, 앱과 함께 OTA로 갱신, `esp_crt_bundle_set()`으로 런타임 교체) |
| 교차 서명 대응 | `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY` |
| A/B 슬롯 | 파티션 `ota_0`·`ota_1` + `otadata` |
| 자체 시험 후 확정·되돌리기 | `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, `esp_ota_mark_app_valid_cancel_rollback()` / `esp_ota_mark_app_invalid_rollback_and_reboot()` |
| 보안 버전 하한 | `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`, `CONFIG_BOOTLOADER_APP_SECURE_VERSION` (eFuse, 32단계까지) |
| OTA 이미지 서명 | Secure Boot v2: ESP32(v3.0 이상)는 RSA-3072 PSS, 공개키 다이제스트를 eFuse에. 부팅할 때와 OTA할 때 모두 검증 |
| 플래시의 키·인증서 보호 | Flash Encryption (+ NVS 암호화) |

재 볼 것: 번들 크기(바이트), `esp_crt_bundle_set()`으로 루트 교체 후 접속, anti-rollback eFuse 값이 올라가는 시점, Secure Boot v2를 켠 뒤 다른 키로 서명한 이미지가 OTA에서 거부되는 로그.

주의: Secure Boot·Flash Encryption의 eFuse는 되돌릴 수 없습니다. 개발 보드로 먼저 하고, 문서의 "개발 모드" 설명을 읽은 뒤 켭니다.

- ESP-IDF 인증서 번들: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/protocols/esp_crt_bundle.html
- ESP-IDF OTA(롤백·안티롤백): https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/ota.html
- Secure Boot v2: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/secure-boot-v2.html
- Flash Encryption: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/flash-encryption.html

## 정리

```bash
kill %1 2>/dev/null            # tls_server.py를 직접 띄웠다면
rm -rf out device
```

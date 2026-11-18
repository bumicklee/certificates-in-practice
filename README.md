# 「서버·앱·ESP32까지, 인증서 실전: TLS·mTLS·코드 서명」 실습 저장소

강의에서 쓰는 실습 스크립트·설정·작은 프로그램을 모아 둔 저장소입니다. 모든 키와 인증서는 **실행할 때 내 PC에서 새로 만들어지고**,
저장소에는 키 파일이 하나도 들어 있지 않습니다. 만들어진 키(`out/`, `keys/`, `demo-pki/` 등)는 `.gitignore`로 빠집니다.
실습용 키는 실습에서만 쓰고, 실제 서비스나 제품에 쓰지 마세요.

## 받기

강의 화면은 이 저장소를 `lab` 폴더로 받았다고 보고 진행합니다.

```bash
git clone https://github.com/bumicklee/certificates-in-practice.git lab
cd lab
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.lock.txt
```

## 준비물

| 무엇 | 버전 | 어디에 쓰나 |
|---|---|---|
| macOS 또는 Linux | — | 모든 실습. 강의 화면은 macOS |
| OpenSSL | **3.5 이상**(`X25519MLKEM768`이 있어야 함). macOS 기본 LibreSSL은 안 됨 | 1~7장 대부분 |
| Docker | Docker Desktop 또는 Docker Engine | acme-pebble, step-ca, mtls, nginx-hardening, supply-chain, ESP32 브로커 |
| Python | 3.12 | 파이썬 스크립트 전체(`requirements.lock.txt`) |
| (선택) ESP-IDF + ESP32 보드 | ESP-IDF v5.5, ESP32-C5 | 8장 ESP32 데모(`esp32/`). 보드가 없으면 PC 쪽 서버·브로커 준비까지 따라 하고 보드 화면은 영상으로 봅니다 |
| (선택) Android 기기 + JDK 17 | Android 9(API 28) 이상, Android SDK | 8장 앱 데모(`android/android-tls-app`), 9-3 키 증명(`android/android-attest-app`) |

## 폴더 지도(강의 수업 번호 기준)

| 섹션 | 수업 | 주제 | 폴더 |
|---|---|---|---|
| 1장 들어가며 | 1-1 | 실습장 준비 | `private-ca` |
| 2장 키 한 쌍과 TLS | 2-1 | 개인키·공개키 한 쌍 | `private-ca`, `chain-demo` |
|  | 2-2 | TLS 1.3 핸드셰이크·양자 내성 | `tls13` |
| 3장 인증서와 신뢰 체인 | 3-1 | 인증서 한 장 읽기 | `private-ca`, `tls13` |
|  | 3-2 | 체인이 깨지는 다섯 가지 | `chain-demo`, `broken-chains` |
|  | 3-3 | 전자서명·타임스탬프·JWT | `signing` |
| 4장 발급과 갱신 | 4-1 | ACME 발급 한 건 | `acme-pebble` |
|  | 4-2 | HTTP-01·DNS-01 | `acme-pebble` |
|  | 4-3 | 자동 갱신과 reload | `acme-pebble` |
|  | 4-4 | ARI와 만료 감시 | `acme-pebble`, `cert-inventory` |
| 5장 사내 CA | 5-1 | 오프라인 루트와 중간 CA | `step-ca` |
|  | 5-2 | 짧은 수명·SSH 인증서 | `step-ca` |
| 6장 mTLS와 TLS 운영 | 6-1 | mTLS와 인증서 신원 | `mtls` |
|  | 6-2 | 앞단 mTLS와 헤더 위조 | `mtls` |
|  | 6-3 | mTLS 운영·DB 접속 | `mtls` |
|  | 6-4 | TLS 하드닝·HSTS | `nginx-hardening` |
| 7장 고리가 끊기면 | 7-1 | CA:TRUE 리프 | `broken-chains`, `chain-demo` |
|  | 7-2 | CAA·서브도메인 탈취 | `domain-check` |
|  | 7-3 | 모바일 신뢰 저장소와 피닝 | `mobile-pins` |
|  | 7-4 | CT 감시 | `ct-watch` |
| 8장 기기와 앱이 서버를 믿는 법 | 8-1 | 기기·앱이 믿는 것 | `esp32/cert-lab`, `android/android-tls-app` |
|  | 8-2 | 서버 확인 실패 세 가지 | `esp32/cert-lab`, `android/android-tls-app` |
|  | 8-3 | ESP32와 앱의 mTLS | `esp32/cert-lab`, `android/android-tls-app`, `mtls` |
|  | 8-4 | 서명된 OTA와 앱 서명 | `esp32/cert-lab`, `embedded-ota`(보드 없이 PC에서) |
|  | 8-5 | Secure Boot(QEMU) | `esp32/qemu-sb` |
| 9장 기기 인증서와 하드웨어 키 증명 | 9-1 | 기기별 인증서 받기 | `iot-provisioning` |
|  | 9-2 | 하드웨어 키 증명 12줄 | `attestation`, `attestation/android-real` |
|  | 9-3 | 내 기기에서 진짜 키 증명 | `attestation/android-real`, `android/android-attest-app` |
|  | 9-4 | App Attest·Matter | `attestation/apple-sim`, `attestation` |
|  | 9-5 | Passkey와 .well-known | `webauthn`, `well-known` |
| 10장 공급망과 운영 | 10-1 | 이미지 서명과 Sigstore | `supply-chain`, `signing` |
|  | 10-2 | 만료와 도입 순서 | `cert-inventory`, `nginx-hardening` |

각 폴더의 `README.md`에 실행 순서와 정리(지우기) 방법이 있습니다. 결과를 파일로 남기는 명령은 `results/`에 쓰고, 이 폴더의 내용도 저장소에 올라가지 않습니다.

## 지켜 주세요

- 서버는 모두 `127.0.0.1`(ESP32 실습만 내 PC의 사설 IP)에만 띄웁니다. 실습이 끝나면 각 폴더의 `down.sh`·`stop`으로 컨테이너를 지웁니다.
- ESP32 실습은 eFuse를 굽지 않습니다. Secure Boot·플래시 암호화는 QEMU(`esp32/qemu-sb`)에서만 해 봅니다.
- 보드를 처음 구울 때는 `esp32/README.md` 2절대로 원래 펌웨어를 먼저 백업합니다. 백업 파일에는 Wi-Fi 설정이 들어 있으니 공유하지 마세요.
- Android 실습은 기기 설정(사용자 CA·시계·개발자 옵션)을 바꾸지 않습니다. 끝나면 앱을 지우고 `adb reverse --remove-all`.

## 라이선스

`LICENSE` 파일을 보세요. `attestation/android-real/data/`의 시험 데이터는 android/keyattestation 저장소의 것으로 Apache-2.0(같은 폴더의 `LICENSE`)을 따릅니다.

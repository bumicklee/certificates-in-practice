# android-tls-app (lab.tlscheck)

8장(8-1~8-4) 앱 데모용 디버그 앱. 사례 하나마다 `HttpsURLConnection`으로 `https://localhost:<포트>/`에 GET 한 번을 하고,
결과 한 줄을 로그(태그 `TlsLab`)와 화면에 낸다.

## 준비

1. 실습 인증서: 저장소 루트(`lab/`)에서 `./private-ca/make_chain.sh`, `./broken-chains/make_broken.sh`.
   깨진 사슬이 `broken-chains/out/base` 아래에 있으므로 앱은 **base 루트**를 믿는다.
2. 앱 자원 만들기(실습 루트·클라이언트 PKCS#12·핀 두 개). 만든 파일은 `.gitignore`로 저장소에서 빠진다(실습 뒤 지워도 된다):
   `./make_assets.sh ../../broken-chains/out`
   → `res/raw/lab_root.pem`, `assets/client.p12`(비밀번호 `lab-only-pass`, 실습 전용), `res/xml/nsc_pin_right.xml`·`nsc_pin_wrong.xml`

## 빌드

Gradle 8.10.2 wrapper + AGP 8.7.2 + JDK 17(Corretto). Android SDK 위치는 `ANDROID_HOME` 환경 변수나 `local.properties`(`sdk.dir=<SDK 경로>`, 저장소에 올리지 않음)로 알려 준다.

    JAVA_HOME=<Corretto 17> ./gradlew assembleDebug                        # nsc_main
    JAVA_HOME=<Corretto 17> ./gradlew assembleDebug -PlabNsc=nsc_pin_wrong  # pin 사례(틀린 핀)
    JAVA_HOME=<Corretto 17> ./gradlew assembleDebug -PlabNsc=nsc_pin_right  # pin 사례(맞는 핀)

## 서버(PC, 127.0.0.1만) — `lab/broken-chains/out`에서

| 포트 | 서버 인증서 | 용도 |
|---|---|---|
| 18460 | base/leaf + base/inter | system · nsc · pin |
| 18461 | 3-san-mismatch/leaf + base/inter | wrongname |
| 18462 | 2-wrong-issuer/leaf + other-inter | unknownroot |
| 18463 | base/leaf + base/inter, `-Verify 1 -CAfile base/root.crt` | mtls-none · mtls-cert |

    openssl s_server -accept 127.0.0.1:18460 -cert base/leaf.crt -key base/leaf.key -cert_chain base/inter.crt -www -quiet &
    adb reverse tcp:18460 tcp:18460     # 포트마다

## 실행

    adb install -r app/build/outputs/apk/debug/app-debug.apk
    adb logcat -c
    adb shell am start -S -W -n lab.tlscheck/.MainActivity --es case <사례>
    adb logcat -d -v raw -s TlsLab:I

| 사례 | 주소 | 기대 |
|---|---|---|
| `system` | https://127.0.0.1:18460/ (NSC domain-config 밖 → 시스템 루트만) | Trust anchor not found |
| `nsc` | https://localhost:18460/ | OK HTTP 200 |
| `wrongname` | https://localhost:18461/ | SSLPeerUnverifiedException: Hostname localhost not verified |
| `unknownroot` | https://localhost:18462/ | Trust anchor not found |
| `pin` | https://localhost:18460/ (빌드의 NSC에 따라) | 틀린 핀 → Pin verification failed / 맞는 핀 → 200 |
| `mtls-none` | https://localhost:18463/ | SSLProtocolException … TLSV1_ALERT_CERTIFICATE_REQUIRED |
| `mtls-cert` | https://localhost:18463/ (assets/client.p12 → KeyManager) | OK HTTP 200 |

클라이언트 키를 assets에 넣은 것은 데모용이다. 실제 앱은 Android Keystore 또는 KeyChain에 둔다.

## 정리(꼭)

    adb uninstall lab.tlscheck
    adb reverse --remove-all
    kill <s_server PID들>      # lsof -nP -iTCP:18460-18463 -sTCP:LISTEN 으로 0개 확인

기기 설정(사용자 CA·시계·개발자 옵션)은 바꾸지 않는다.

# android-attest-app (lab.attest)

수업 9-3 「내 기기에서 진짜 키 증명」용 디버그 앱. 서버가 준 챌린지를 넣어 AndroidKeyStore에 EC P-256 키를 만들고,
키 증명 인증서 사슬을 PEM으로 앱 전용 폴더에 저장한다. 키·인증서 말고는 아무것도 읽거나 보내지 않는다.

## 빌드

Gradle 8.10.2 wrapper + AGP 8.7.2 + JDK 17. Android SDK 위치는 `ANDROID_HOME` 또는 `local.properties`(`sdk.dir=…`, 저장소에 올리지 않음).

    ./gradlew assembleDebug

## 실행

    python3 -c "import os; print(os.urandom(32).hex())" > challenge.txt     # 서버가 줄 챌린지 흉내
    adb install -r app/build/outputs/apk/debug/app-debug.apk
    adb logcat -c
    adb shell am start -S -W -n lab.attest/.MainActivity --es challenge $(cat challenge.txt)      # StrongBox: --ez strongbox true
    adb logcat -d -v raw -s AttestLab:I
    adb pull /storage/emulated/0/Android/data/lab.attest/files/lab-key-tee-chain.pem device-chain.pem

## 서버 쪽 판정(체크리스트 12줄)

앱 서명 인증서의 SHA-256(콜론 없이 hex)을 구한 뒤, `attestation/android-real`의 검증기로 판정한다.

    $ANDROID_HOME/build-tools/<버전>/apksigner verify --print-certs app/build/outputs/apk/debug/app-debug.apk | grep SHA-256
    ../../.venv/bin/python -I verify_device_chain.py device-chain.pem challenge.txt <서명 인증서 sha256 hex>

다른 챌린지로는 6번, 다른 앱 패키지 정책으로는 10번이 FAIL로 바뀌는 것도 함께 출력한다.

## 정리(꼭)

    adb uninstall lab.attest            # 키스토어의 실습 키도 함께 지워진다
    rm -f challenge.txt device-chain.pem

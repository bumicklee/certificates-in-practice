# iot-provisioning (수업 9-1)

AWS IoT 플릿 프로비저닝(클레임 방식)을 **로컬 Mosquitto 위에서** 재현합니다. 공용 클레임 인증서를 가진 기기가 키를 스스로 만들고, CSR을 보내 기기별 인증서를 받고, 그 인증서로 다시 접속해 **자기 토픽만** 씁니다. AWS는 부르지 않습니다. 실계정용 파일은 [`aws/`](aws/README.md)에 있습니다.

## 준비물

- Mosquitto 2.x (`/opt/homebrew/sbin/mosquitto`, `mosquitto_pub`)
- OpenSSL 3.x, `lab/.venv` (paho-mqtt 2.x, cryptography)
- 포트 `127.0.0.1:18480`

## 구성

```
기기(device.py) ──mTLS──► Mosquitto 127.0.0.1:18480 ◄──mTLS── 프로비저닝 서비스(prov_service.py) ─ 훅(hook.py) ─ allowlist.json
   클레임 인증서 → 자기 인증서            require_certificate true                     발급 CA: out/ca/issuing.*
                                          use_identity_as_username true (CN = 사용자)  레지스트리: out/registry.json
                                          acl_file acl                     ◄──mTLS── 텔레메트리 백엔드(telemetry_backend.py)
```

| 파일 | 하는 일 |
|---|---|
| `make_pki.sh` | Lab IoT Root → Device Issuing CA, 브로커 서버 인증서, 클레임(`claim-factory-line-1`), 서비스(`prov-service`), 백엔드(`telemetry-backend`) 인증서 |
| `mosquitto.conf`, `acl` | TLS 리스너, 인증서 필수, CN = 사용자 이름, 토픽 권한 |
| `prov_service.py` | `$prov/<클레임 신원>/<clientId>/provision`을 받아 CSR 확인 → 훅 → 서명 → `accepted`/`rejected` |
| `hook.py` | 사전 프로비저닝 훅(로컬판). 입력·출력 모양이 AWS 훅 Lambda와 같다 |
| `device.py` | 기기. `provision`(키 생성 → CSR → 인증서 → 재접속 → 텔레메트리), `publish`(한 번 발행, PUBACK 이유 코드 출력) |
| `telemetry_backend.py` | `devices/+/telemetry`를 받아 출력 |
| `run_demo.sh` | 전부 띄우고 시나리오를 돌리고 모두 끈다 |

## ACL (요점)

```
user claim-factory-line-1
topic deny devices/#                                   # 클레임은 텔레메트리 금지
pattern write $prov/%u/%c/provision                    # %u = 인증서 CN, %c = clientId(= 시리얼)
pattern read  $prov/%u/%c/provision/accepted
pattern read  $prov/%u/%c/provision/rejected

pattern write devices/%u/telemetry                     # 기기: CN(= 사물 이름) 자기 토픽만
pattern read  devices/%u/commands
```

- `%u`는 브로커가 인증서에서 꺼낸 CN이라 클라이언트가 바꿀 수 없습니다. 그래서 서비스는 토픽의 `<클레임 신원>` 칸을 "누가 보냈나"로 믿을 수 있습니다.
- AWS IoT는 응답을 **요청한 그 연결로만** 돌려줍니다. Mosquitto에는 그런 기능이 없어서 `%c`(clientId)로 응답 토픽을 나눴습니다.
- Mosquitto의 `pattern`은 **모든 사용자**에게 적용됩니다. 그래서 기기 인증서도 `$prov/<자기 CN>/…`에는 쓸 수 있고(시나리오 6), 서비스가 "클레임 신원이 아님"으로 거부합니다. AWS는 인증서마다 정책을 붙이므로 이 틈이 없습니다.

## 실행

```bash
cd lab/iot-provisioning
./run_demo.sh > ../results/17-provisioning-demo.txt 2>&1
```

손으로 하려면 터미널 셋:

```bash
./make_pki.sh && chmod 600 acl
/opt/homebrew/sbin/mosquitto -c mosquitto.conf                 # 1
../.venv/bin/python prov_service.py                            # 2
../.venv/bin/python telemetry_backend.py                       # 3
../.venv/bin/python device.py provision --serial SN-0000-0001
../.venv/bin/python device.py publish --serial SN-0000-0001 --as device --topic devices/boiler-SN-0000-0002/telemetry
```

## 결과 (2026-10-31 실측, `../results/17-provisioning-demo.txt`)

| # | 시나리오 | 결과 |
|---|---|---|
| 0 | 인증서 없이 접속 | TLS 단계에서 끊김(`peer did not return a certificate`) |
| 1 | SN-0000-0001·0002 프로비저닝 | `accepted`, CN `boiler-SN-0000-000x`, 재접속 후 텔레메트리 `PUBACK Success` |
| 2 | 허용 목록 밖 SN-0000-0099 | `rejected 403 … not in allowlist` |
| 3 | 클레임 인증서로 텔레메트리 | `PUBACK Not authorized`, 브로커 로그 `Denied PUBLISH` |
| 4 | 기기 A가 기기 B 토픽에 | `PUBACK Not authorized` (자기 토픽은 `Success`) |
| 5 | 이미 등록된 SN-0000-0001 재사용 | `rejected 403 … already provisioned` |
| 6 | 기기 인증서로 프로비저닝 토픽 | 브로커는 통과, 서비스가 `not a provisioning claim`으로 거부 |

## AWS와 다른 점

| 이 실습 | AWS IoT |
|---|---|
| 요청 한 번(CSR + 시리얼). 훅이 통과한 **뒤에만** 서명 | `CreateCertificateFromCsr`가 먼저 인증서를 만들고(`PENDING_ACTIVATION`), `RegisterThing`에서 훅이 통과해야 활성화. 소유 토큰 1시간 안에 등록하지 않으면 인증서 삭제 |
| 인증서 CN = 사물 이름, ACL `%u` | 정책 변수 `${iot:Connection.Thing.ThingName}` (+ clientId = 사물 이름) |
| 레지스트리 = JSON 파일 | 사물 레지스트리 + `ThingPrincipalType: EXCLUSIVE_THING` |
| 허용 목록 = JSON 파일 | 훅 Lambda가 DynamoDB 조건부 갱신으로 허용·중복을 한 번에 본다(`aws/pre_provisioning_hook.py`) |

## 정리

```bash
pkill -f "mosquitto -c mosquitto.conf"; pkill -f prov_service.py; pkill -f telemetry_backend.py
rm -rf out
```

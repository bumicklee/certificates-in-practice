# iot-provisioning/aws (26편, AWS 실계정용 · 선택)

이 폴더의 파일은 **AWS를 부르지 않고 작성했습니다.** 로컬에서 실제로 돌린 것은 훅 Lambda 단위 시험뿐입니다(`../../results/17-hook-unittest.txt`). 실계정에서 돌린 결과는 `【직접 해 보기: AWS】`로 남깁니다. 계정 ID `111122223333`, 리전 `ap-northeast-2`, ARN은 모두 예시 값입니다.

## 파일

| 파일 | 무엇 |
|---|---|
| `fleet-provisioning-template.json` | 플릿 프로비저닝 템플릿. 사물 이름 `boiler-<SerialNumber>`, 인증서 `EXCLUSIVE_THING`, 정책은 이름으로 참조 |
| `pre-provisioning-hook.json` | 템플릿에 붙이는 훅 설정(`targetArn`, `payloadVersion: 2020-04-01`) |
| `claim-policy.json` | 클레임 인증서 정책. `$aws/certificates/create-from-csr/*`, `$aws/provisioning-templates/boiler-template/provision/*`만 |
| `device-policy.json` | 기기 정책. `${iot:Connection.Thing.ThingName}`로 자기 토픽만, `iot:Connection.Thing.IsAttached` |
| `pre_provisioning_hook.py` | 훅 Lambda. 템플릿·클레임 확인, clientId = 시리얼, DynamoDB 조건부 갱신으로 허용 목록·중복을 한 번에 |
| `test_pre_provisioning_hook.py` | 위 Lambda의 로컬 단위 시험(가짜 DynamoDB) |
| `jitr_activate.py` | JITR: `$aws/events/certificates/registered/<caCertificateId>` 규칙 → Lambda가 검사 후 사물·정책·`ACTIVE` |
| `direct_issue_lambda.py` | 직접 발급 API 스케치: API Gateway + Lambda + AWS Private CA `IssueCertificate` |
| `roles-anywhere-config.ini` | IAM Roles Anywhere `credential_process` 설정 예 |
| `cleanup.sh` | 정리 명령 목록(맨 위 `exit 0`. 한 줄씩 확인하며 복사해 쓴다) |

## 단위 시험 (로컬)

```bash
cd lab/iot-provisioning/aws
../../.venv/bin/python -m unittest -v test_pre_provisioning_hook
```

2026-10-31 실측: 7개 시험 모두 `ok` (허용, 목록 밖, 중복, clientId 불일치, 끈 클레임, 다른 템플릿, 출력 필수 키).

## 실계정 순서 (명령만 · 【직접 해 보기: AWS】)

```bash
# 0) 기기 정책·클레임 정책
aws iot create-policy --policy-name boiler-device-policy --policy-document file://device-policy.json
aws iot create-policy --policy-name boiler-claim-policy  --policy-document file://claim-policy.json
# 1) 프로비저닝 역할(AWSIoTThingsRegistration 관리형 정책을 붙인 역할, 신뢰 주체 iot.amazonaws.com)
# 2) 시리얼 테이블과 훅 Lambda
aws dynamodb create-table --table-name boiler-serials --attribute-definitions AttributeName=serial,AttributeType=S \
  --key-schema AttributeName=serial,KeyType=HASH --billing-mode PAY_PER_REQUEST
aws lambda add-permission --function-name boiler-pre-provisioning-hook --statement-id iot-hook \
  --action lambda:InvokeFunction --principal iot.amazonaws.com \
  --source-arn arn:aws:iot:ap-northeast-2:111122223333:provisioningtemplate/boiler-template \
  --source-account 111122223333                       # 혼동된 대리인 방지
# 3) 템플릿
aws iot create-provisioning-template --template-name boiler-template --enabled \
  --provisioning-role-arn arn:aws:iam::111122223333:role/boiler-provisioning-role \
  --template-body file://fleet-provisioning-template.json --pre-provisioning-hook file://pre-provisioning-hook.json
# 4) 클레임 인증서: 공장 CA로 만든 인증서를 등록하거나 create-keys-and-certificate로 만들고 claim 정책을 붙인다
```

재 볼 것: 성공·허용 목록 밖·중복 세 경우의 `RegisterThing` 응답(`rejected`의 `statusCode`/`errorCode`), 훅 Lambda 지연 시간(5초 제한), 클레임 인증서 비활성화 후 새 기기 프로비저닝이 막히는지, CloudWatch 지표.

## 사실 메모 (2026-10-31 공식 문서 확인)

- 클레임 방식: 소유 토큰(`certificateOwnershipToken`) 1시간. 지나면 미활성 인증서 삭제. 새 인증서 저장 후 **끊고 새 인증서로 재접속**해야 한다. 응답은 요청한 그 MQTT 연결로 돌아온다.
- 신뢰 사용자: `CreateProvisioningClaim`의 임시 클레임 인증서 5분.
- 훅: 출력에 `allowProvisioning`·`parameterOverrides`. 5초 안에 돌아오지 않으면 실패. Lambda 실패나 거부는 `ACCESS_DENIED`.
- `CreateKeysAndCertificate`: AWS가 RSA 2048 키를 만들어 돌려준다(개인키가 네트워크로 온다). AWS IoT가 만든 인증서는 2049-12-31T23:59:59Z에 만료.
- JITR: 첫 접속에서 인증서를 `PENDING_ACTIVATION`으로 등록하고 `$aws/events/certificates/registered/<caCertificateId>`에 이벤트를 낸 뒤 연결을 끊는다. 기기는 재접속 전략이 있어야 한다. SNI 필수.

## AWS Private CA 비용 (직접 발급 API를 쓸 때)

2026-10-31 기준, https://aws.amazon.com/private-ca/pricing/

| 항목 | 범용 모드 | 단기 인증서 모드 |
|---|---|---|
| CA 운영 | CA당 월 400달러 | CA당 월 50달러 |
| 발급(1~1,000장 구간) | 장당 0.75달러 | 장당 0.058달러 |

- 만들어 두기만 해도 월 요금이 붙습니다. 이 실습은 Private CA를 **만들지 않습니다.**
- AWS IoT 플릿 프로비저닝(①~④)으로 받는 인증서는 Amazon 루트 아래에서 AWS IoT가 발급하므로 이 표와 무관합니다.

## IAM Roles Anywhere

기기(또는 공장 서버)가 X.509 인증서로 **임시 AWS 자격 증명**을 받습니다. 신뢰 앵커(CA)·프로필·역할을 만들고, 도우미 `aws_signing_helper credential-process`를 `credential_process`에 연결합니다(`roles-anywhere-config.ini`). 필수 옵션은 `--certificate`, `--private-key`, `--trust-anchor-arn`, `--profile-arn`, `--role-arn`이고, 중간 CA는 `--intermediates`, 세션 길이는 `--session-duration`(900~43200초)입니다. 도우미 최신판은 1.8.5(2026-08-24)입니다.

## 정리

`cleanup.sh`의 명령을 위에서부터 한 줄씩. 순서: 정책 분리 → 사물 분리 → 인증서 비활성화 → 삭제 → 템플릿·정책·Lambda·역할·테이블 → (JITR) CA·규칙 → (만들었다면) Private CA.

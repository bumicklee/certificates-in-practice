#!/usr/bin/env bash
# 26편 AWS 실계정 실습 정리 명령 목록. 자동 실행하지 말고 한 줄씩 확인하며 쓴다.  【직접 해 보기: AWS】
# 순서가 중요하다: 정책 분리 → 사물 분리 → 인증서 비활성화 → 삭제
exit 0
REGION=ap-northeast-2
# 1) 기기 인증서·사물 (시리얼마다)
aws iot detach-policy --policy-name boiler-device-policy --target "$CERT_ARN" --region $REGION
aws iot detach-thing-principal --thing-name boiler-SN-0000-0001 --principal "$CERT_ARN" --region $REGION
aws iot update-certificate --certificate-id "$CERT_ID" --new-status INACTIVE --region $REGION
aws iot delete-certificate --certificate-id "$CERT_ID" --region $REGION
aws iot delete-thing --thing-name boiler-SN-0000-0001 --region $REGION
# 2) 클레임 인증서
aws iot detach-policy --policy-name boiler-claim-policy --target "$CLAIM_CERT_ARN" --region $REGION
aws iot update-certificate --certificate-id "$CLAIM_CERT_ID" --new-status INACTIVE --region $REGION
aws iot delete-certificate --certificate-id "$CLAIM_CERT_ID" --region $REGION
# 3) 템플릿·정책·Lambda·역할·테이블
aws iot delete-provisioning-template --template-name boiler-template --region $REGION
aws iot delete-policy --policy-name boiler-claim-policy --region $REGION
aws iot delete-policy --policy-name boiler-device-policy --region $REGION
aws lambda delete-function --function-name boiler-pre-provisioning-hook --region $REGION
aws iam detach-role-policy --role-name boiler-provisioning-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration
aws iam delete-role --role-name boiler-provisioning-role
aws dynamodb delete-table --table-name boiler-serials --region $REGION
# 4) JITR을 썼다면: CA 자동 등록 끄기 → CA 비활성화 → 삭제, IoT 규칙 삭제
aws iot update-ca-certificate --certificate-id "$CA_ID" --new-auto-registration-status DISABLE --new-status INACTIVE --region $REGION
aws iot delete-ca-certificate --certificate-id "$CA_ID" --region $REGION
aws iot delete-topic-rule --rule-name boiler_jitr --region $REGION
# 5) Private CA를 만들었다면 (만든 동안 월 요금): 비활성화 → 삭제(복구 기간 7~30일)
aws acm-pca update-certificate-authority --certificate-authority-arn "$PCA_ARN" --status DISABLED --region $REGION
aws acm-pca delete-certificate-authority --certificate-authority-arn "$PCA_ARN" --permanent-deletion-time-in-days 7 --region $REGION

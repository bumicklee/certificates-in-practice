"""사전 프로비저닝 훅 Lambda (Python 3.12). AWS 실계정에서만 배포한다. 로컬에서는 test_pre_provisioning_hook.py로 시험한다.

입력(AWS IoT가 보냄): claimCertificateId, certificateId, certificatePem, templateArn, clientId, parameters
출력(필수 두 칸): allowProvisioning, parameterOverrides   — 5초 안에 돌려줘야 한다

DynamoDB 테이블 boiler-serials (파티션 키 serial):
  {serial: "SN-0000-0001", status: "manufactured"}   ← 공장 생산 관리 시스템이 넣는다
허용 목록 검사와 중복 검사를 조건부 갱신 한 번으로 한다(복제 기기 두 대가 동시에 와도 하나만 통과).
"""
import json, logging, os

log = logging.getLogger(); log.setLevel(logging.INFO)
TABLE = os.environ.get("SERIAL_TABLE", "boiler-serials")
ALLOWED_CLAIMS = set(filter(None, os.environ.get("ALLOWED_CLAIM_CERT_IDS", "").split(",")))
EXPECTED_TEMPLATE_SUFFIX = ":provisioningtemplate/boiler-template"
_tbl = None


def _table():
    global _tbl
    if _tbl is None:
        import boto3  # Lambda 런타임에 들어 있다
        _tbl = boto3.resource("dynamodb").Table(TABLE)
    return _tbl


def _deny(reason, event):
    log.warning(json.dumps({"decision": "deny", "reason": reason, "clientId": event.get("clientId"),
                            "claimCertificateId": event.get("claimCertificateId")}))
    return {"allowProvisioning": False, "parameterOverrides": {}}


def handler(event, context):
    serial = (event.get("parameters") or {}).get("SerialNumber", "")
    if not event.get("templateArn", "").endswith(EXPECTED_TEMPLATE_SUFFIX):
        return _deny("unexpected template", event)
    if ALLOWED_CLAIMS and event.get("claimCertificateId") not in ALLOWED_CLAIMS:
        return _deny("claim certificate not allowed (disabled line?)", event)
    if not serial.startswith("SN-") or event.get("clientId") != serial:
        return _deny("clientId must equal SerialNumber", event)
    try:
        _table().update_item(
            Key={"serial": serial},
            UpdateExpression="SET #s = :p, certificateId = :c, claim = :cl",
            ConditionExpression="#s = :m",          # 공장에서 만든 기록이 있고, 아직 등록 전일 때만
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":p": "provisioned", ":m": "manufactured",
                                       ":c": event.get("certificateId", ""), ":cl": event.get("claimCertificateId", "")})
    except Exception as e:  # botocore ClientError
        if getattr(e, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return _deny("serial unknown or already provisioned", event)
        raise                                       # 그 밖의 오류 → Lambda 실패 → ACCESS_DENIED
    log.info(json.dumps({"decision": "allow", "serial": serial}))
    return {"allowProvisioning": True, "parameterOverrides": {}}

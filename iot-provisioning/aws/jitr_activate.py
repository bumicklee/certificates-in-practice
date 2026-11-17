"""JITR(Just-in-Time Registration) 활성화 Lambda — 코드만. 실행하지 않았다. 【직접 해 보기: AWS】

흐름
  1) 공장 CA를 AWS IoT에 등록하고 자동 등록을 켠다(register-ca-certificate --allow-auto-registration).
  2) 그 CA로 서명된 기기 인증서가 처음 접속하면 AWS IoT가 인증서를 PENDING_ACTIVATION으로 등록하고
     $aws/events/certificates/registered/<caCertificateId> 로 이벤트를 보낸 뒤 연결을 끊는다.
     → 기기는 백오프하며 다시 접속해야 한다.
  3) IoT 규칙  SELECT *, clientid() AS clientid FROM '$aws/events/certificates/registered/<caCertificateId>'
     가 이 Lambda를 부른다. Lambda는 검사 후 사물을 만들고 정책을 붙이고 ACTIVE로 바꾼다.

cryptography는 Lambda 기본 런타임에 없으니 레이어로 넣는다.
"""
import json, logging, os, re
import boto3
from cryptography import x509
from cryptography.x509.oid import NameOID

log = logging.getLogger(); log.setLevel(logging.INFO)
iot = boto3.client("iot")
EXPECTED_CA_ID = os.environ["EXPECTED_CA_CERT_ID"]
POLICY = os.environ.get("DEVICE_POLICY", "boiler-device-policy")
CN_RE = re.compile(r"^boiler-SN-\d{4}-\d{4}$")


def handler(event, context):
    cert_id, ca_id = event["certificateId"], event["caCertificateId"]
    if ca_id != EXPECTED_CA_ID or event.get("certificateStatus") != "PENDING_ACTIVATION":
        log.warning("ignore: ca=%s status=%s", ca_id, event.get("certificateStatus")); return
    desc = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]
    cert = x509.load_pem_x509_certificate(desc["certificatePem"].encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if not CN_RE.match(cn) or event.get("clientid") != cn:
        log.warning("deny: cn=%s clientid=%s", cn, event.get("clientid"))
        iot.update_certificate(certificateId=cert_id, newStatus="REVOKED"); return
    # 여기서 생산 기록(DynamoDB 등)과 대조하고 CRL을 확인한다(AWS 문서 권장)
    iot.create_thing(thingName=cn, attributePayload={"attributes": {"model": "boiler-ctl"}})
    iot.attach_thing_principal(thingName=cn, principal=desc["certificateArn"], thingPrincipalType="EXCLUSIVE_THING")
    iot.attach_policy(policyName=POLICY, target=desc["certificateArn"])
    iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
    log.info(json.dumps({"activated": cn, "certificateId": cert_id}))

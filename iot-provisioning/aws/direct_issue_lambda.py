"""직접 발급 API 스케치 — API Gateway(IAM 인증 또는 mTLS) + Lambda + AWS Private CA IssueCertificate.
코드만. 실행하지 않았다(Private CA는 만들기만 해도 월 요금이 붙는다). 【직접 해 보기: AWS】

쓰는 곳: AWS IoT Core가 아닌 브로커(Mosquitto·EMQX), 자체 백엔드 mTLS, IAM Roles Anywhere용 인증서.
요청:  POST /devices/{serial}/certificate   body {"csr": "<PEM>"}
응답:  {"certificatePem": "...", "chainPem": "..."}
"""
import json, os, re, uuid
import boto3
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

pca = boto3.client("acm-pca")
CA_ARN = os.environ["PCA_ARN"]                       # arn:aws:acm-pca:<region>:<acct>:certificate-authority/<id>
TEMPLATE = "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
SERIAL_RE = re.compile(r"^SN-\d{4}-\d{4}$")


def handler(event, context):
    serial = event["pathParameters"]["serial"]
    if not SERIAL_RE.match(serial):
        return {"statusCode": 400, "body": "bad serial"}
    # 호출자 확인: 공장 라인 IAM 역할만 (API Gateway IAM 인증의 caller ARN)
    caller = event["requestContext"].get("identity", {}).get("userArn", "")
    if not caller.endswith(":assumed-role/factory-line-provisioner/" + caller.split("/")[-1]):
        return {"statusCode": 403, "body": "caller not allowed"}
    csr_pem = json.loads(event["body"])["csr"].encode()
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid or not isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
        return {"statusCode": 400, "body": "bad csr"}
    # (여기서 허용 목록·중복 검사: 훅 Lambda와 같은 DynamoDB 조건부 갱신)
    # 주의: Subject는 CSR 값을 쓴다. CN을 강제하려면 APIPassthrough 템플릿 + ApiPassthrough 인자로 Subject를 넘긴다.
    r = pca.issue_certificate(
        CertificateAuthorityArn=CA_ARN, Csr=csr_pem, SigningAlgorithm="SHA256WITHECDSA",
        TemplateArn=TEMPLATE, Validity={"Value": 365, "Type": "DAYS"},
        IdempotencyToken=serial.replace("-", "")[:36])   # 같은 시리얼 재시도는 같은 결과
    pca.get_waiter("certificate_issued").wait(CertificateAuthorityArn=CA_ARN, CertificateArn=r["CertificateArn"])
    got = pca.get_certificate(CertificateAuthorityArn=CA_ARN, CertificateArn=r["CertificateArn"])
    return {"statusCode": 200, "body": json.dumps({"certificatePem": got["Certificate"],
                                                   "chainPem": got["CertificateChain"]})}

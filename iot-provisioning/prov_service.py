#!/usr/bin/env python3
"""로컬 프로비저닝 서비스 (26편). AWS IoT 플릿 프로비저닝(클레임 방식)의 흐름을 Mosquitto 위에서 흉내 낸다.

  요청: $prov/<클레임 신원>/<clientId>/provision           {"csr": PEM, "parameters": {"SerialNumber": ...}}
  응답: $prov/<클레임 신원>/<clientId>/provision/accepted  {"thingName", "certificateId", "certificatePem"}
        $prov/<클레임 신원>/<clientId>/provision/rejected  {"statusCode", "errorCode", "errorMessage"}

토픽의 <클레임 신원>은 브로커가 인증서 CN으로 강제한다(ACL pattern %u). 그래서 서비스는 이 칸을
"누가 보냈나"로 믿을 수 있다. 기기 개인키는 기기 밖으로 나오지 않는다. 서비스는 CSR의 공개키만 쓴다.

AWS와 다른 점: AWS는 CreateCertificateFromCsr로 인증서를 먼저 만들고(비활성), RegisterThing에서 훅이
통과해야 활성화한다. Mosquitto에는 '비활성 인증서'가 없어서, 여기서는 훅이 통과한 뒤에만 서명한다.
"""
import datetime as dt, hashlib, json, os, signal, sys

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from hook import pre_provisioning_hook, REG

HERE = os.path.dirname(os.path.abspath(__file__))
O = lambda *p: os.path.join(HERE, "out", *p)
CLAIM_IDENTITIES = {"claim-factory-line-1"}          # AWS에서는 클레임 인증서 ID 목록
TEMPLATE_ARN = "local:provisioningtemplate/boiler-template"

ISS_CERT = x509.load_pem_x509_certificate(open(O("ca/issuing.crt"), "rb").read())
ISS_KEY = serialization.load_pem_private_key(open(O("ca/issuing.key"), "rb").read(), None)


def log(*a): print(dt.datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def sign_device_cert(csr: x509.CertificateSigningRequest, thing: str) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab IoT Example"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, thing)]))   # CSR의 Subject는 쓰지 않는다
            .issuer_name(ISS_CERT.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ISS_KEY.public_key()), critical=False)
            .sign(ISS_KEY, hashes.SHA256()))


def on_message(c, _u, msg):
    parts = msg.topic.split("/")             # $prov / <identity> / <clientId> / provision
    ident, client_id = parts[1], parts[2]
    reply = f"$prov/{ident}/{client_id}/provision"

    def reject(code, why):
        log(f"REJECT {client_id} ({ident}): {why}")
        c.publish(reply + "/rejected", json.dumps({"statusCode": code, "errorCode": "AccessDenied" if code == 403
                                                   else "InvalidRequest", "errorMessage": why}), qos=1)

    if ident not in CLAIM_IDENTITIES:
        return reject(403, f"identity {ident!r} is not a provisioning claim")
    try:
        req = json.loads(msg.payload)
        csr = x509.load_pem_x509_csr(req["csr"].encode())
    except Exception as e:
        return reject(400, f"bad request: {e}")
    if not csr.is_signature_valid:                       # CSR 서명 = 개인키를 가진 쪽이 보냈다는 증명
        return reject(400, "CSR signature invalid")
    pk = csr.public_key()
    if not (isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name == "secp256r1"):
        return reject(400, "only EC P-256 keys accepted")
    event = {"claimCertificateId": ident, "certificateId": "(pending)", "certificatePem": "(pending)",
             "templateArn": TEMPLATE_ARN, "clientId": client_id, "parameters": req.get("parameters", {})}
    res = pre_provisioning_hook(event)
    log(f"hook {client_id}: allowProvisioning={res['allowProvisioning']} ({res['reason']})")
    if not res["allowProvisioning"]:
        return reject(403, res["reason"])
    thing = res["parameterOverrides"]["ThingName"]
    cert = sign_device_cert(csr, thing)
    pem = cert.public_bytes(serialization.Encoding.PEM) + ISS_CERT.public_bytes(serialization.Encoding.PEM)
    cid = cert.fingerprint(hashes.SHA256()).hex()
    reg = json.load(open(REG)) if os.path.exists(REG) else {}
    reg[event["parameters"]["SerialNumber"]] = {"thingName": thing, "certificateId": cid,
                                                "certSerial": hex(cert.serial_number),
                                                "provisionedAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                                                "claim": ident}
    json.dump(reg, open(REG, "w"), indent=2)
    log(f"ISSUED {thing} certificateId={cid[:16]}… (CN={thing}, 365d, clientAuth)")
    c.publish(reply + "/accepted", json.dumps({"thingName": thing, "certificateId": cid,
                                               "certificatePem": pem.decode()}), qos=1)


def main():
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="prov-service", protocol=mqtt.MQTTv5)
    c.tls_set(ca_certs=O("ca/root.crt"), certfile=O("svc/svc.crt"), keyfile=O("svc/svc.key"))
    c.on_connect = lambda cl, u, f, rc, p: (log(f"connected as prov-service rc={rc}"),
                                            cl.subscribe("$prov/+/+/provision", qos=1))
    c.on_message = on_message
    signal.signal(signal.SIGTERM, lambda *_: (c.disconnect(), sys.exit(0)))
    c.connect("127.0.0.1", 18480)
    c.loop_forever()


if __name__ == "__main__":
    main()

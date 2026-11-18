#!/usr/bin/env python3
"""기기 시뮬레이터 (수업 9-1).

  device.py provision --serial SN-0000-0001     클레임 인증서로 접속 → 키 생성(기기 안) → CSR 전송 → 인증서 받기
                                                → 끊고 내 인증서로 다시 접속 → 텔레메트리 한 번
  device.py publish --serial S --as device|claim --topic T   한 번 발행하고 PUBACK 이유 코드를 출력
"""
import argparse, json, os, shutil, sys, threading, time

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
O = lambda *p: os.path.join(HERE, "out", *p)
CLAIM = "claim-factory-line-1"


def client(cid, cert, key):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5)
    c.tls_set(ca_certs=O("ca/root.crt"), certfile=cert, keyfile=key)
    return c


def publish_once(c, topic, payload):
    done = threading.Event(); res = {}
    c.on_publish = lambda cl, u, mid, rc, props: (res.setdefault("rc", rc), done.set())
    c.publish(topic, payload, qos=1)
    done.wait(5)
    return res.get("rc")


def provision(serial):
    final = O("devices", serial)
    d = O("devices", serial + ".pending")         # 성공하기 전에는 기존 기기 파일을 건드리지 않는다
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    # 1) 키는 기기 안에서 만든다. 파일 권한 600. 실제 기기라면 보안 칩 안에서 만들고 꺼낼 수 없게 한다
    key = ec.generate_private_key(ec.SECP256R1())
    kp = os.path.join(d, "device.key")
    with open(os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, serial)]))
           .sign(key, hashes.SHA256()))
    print(f"[{serial}] key generated on device (P-256), CSR {len(csr.public_bytes(serialization.Encoding.PEM))} bytes")

    # 2) 공용 클레임 인증서로 접속. clientId = 시리얼
    c = client(serial, O("claim/claim.crt"), O("claim/claim.key"))
    base = f"$prov/{CLAIM}/{serial}/provision"
    got = threading.Event(); ans = {}

    def on_msg(cl, u, m):
        ans["topic"], ans["body"] = m.topic, json.loads(m.payload); got.set()
    c.on_message = on_msg
    c.on_connect = lambda cl, u, f, rc, p: print(f"[{serial}] connected with CLAIM cert (CN={CLAIM}) rc={rc}")
    c.connect("127.0.0.1", 18480); c.loop_start(); time.sleep(0.3)
    c.subscribe([(base + "/accepted", 1), (base + "/rejected", 1)]); time.sleep(0.3)
    c.publish(base, json.dumps({"csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
                                "parameters": {"SerialNumber": serial}}), qos=1)
    print(f"[{serial}] → {base}")
    got.wait(5); c.disconnect(); c.loop_stop()
    if not got.is_set():
        print(f"[{serial}] no answer"); return 1
    if ans["topic"].endswith("/rejected"):
        print(f"[{serial}] ← rejected {ans['body']}"); shutil.rmtree(d); return 1
    b = ans["body"]
    open(os.path.join(d, "device.crt"), "w").write(b["certificatePem"])
    json.dump({"thingName": b["thingName"]}, open(os.path.join(d, "thing.json"), "w"))
    os.rename(d, final); d = final; kp = os.path.join(d, "device.key")
    leaf = x509.load_pem_x509_certificate(b["certificatePem"].encode())
    print(f"[{serial}] ← accepted thingName={b['thingName']} subject={leaf.subject.rfc4514_string()} "
          f"notAfter={leaf.not_valid_after_utc:%Y-%m-%d} (cert saved, claim session closed)")

    # 3) 내 인증서로 다시 접속(AWS도 '저장 → 끊기 → 재접속'을 요구한다)
    thing = b["thingName"]
    c2 = client(thing, os.path.join(d, "device.crt"), kp)
    c2.on_connect = lambda cl, u, f, rc, p: print(f"[{serial}] reconnected with OWN cert (CN={thing}) rc={rc}")
    c2.connect("127.0.0.1", 18480); c2.loop_start(); time.sleep(0.3)
    rc = publish_once(c2, f"devices/{thing}/telemetry", json.dumps({"tempC": 41.5}))
    print(f"[{serial}] publish devices/{thing}/telemetry → PUBACK {rc}")
    c2.disconnect(); c2.loop_stop()


def publish(serial, who, topic):
    d = O("devices", serial)
    if who == "claim":
        c, label = client(serial, O("claim/claim.crt"), O("claim/claim.key")), f"CLAIM cert (CN={CLAIM})"
    else:
        thing = json.load(open(os.path.join(d, "thing.json")))["thingName"]
        c, label = client(thing, os.path.join(d, "device.crt"), os.path.join(d, "device.key")), f"OWN cert (CN={thing})"
    c.connect("127.0.0.1", 18480); c.loop_start(); time.sleep(0.3)
    rc = publish_once(c, topic, json.dumps({"tempC": 99.9}))
    print(f"[{serial}] as {label}: publish {topic} → PUBACK {rc}")
    c.disconnect(); c.loop_stop()


def main():
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("provision"); p.add_argument("--serial", required=True)
    p = sp.add_parser("publish"); p.add_argument("--serial", required=True)
    p.add_argument("--as", dest="who", choices=["device", "claim"], required=True); p.add_argument("--topic", required=True)
    a = ap.parse_args()
    return (provision(a.serial) if a.cmd == "provision" else publish(a.serial, a.who, a.topic)) or 0


if __name__ == "__main__":
    sys.exit(main())

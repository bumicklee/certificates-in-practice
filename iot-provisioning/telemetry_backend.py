#!/usr/bin/env python3
"""텔레메트리 수신 백엔드 (CN telemetry-backend). devices/+/telemetry만 읽는다. 받은 것을 그대로 출력한다."""
import datetime as dt, os, signal, sys
import paho.mqtt.client as mqtt
HERE = os.path.dirname(os.path.abspath(__file__)); O = lambda *p: os.path.join(HERE, "out", *p)
c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="telemetry-backend", protocol=mqtt.MQTTv5)
c.tls_set(ca_certs=O("ca/root.crt"), certfile=O("backend/backend.crt"), keyfile=O("backend/backend.key"))
c.on_connect = lambda cl, u, f, rc, p: (print("backend connected", rc, flush=True), cl.subscribe("devices/+/telemetry", qos=1))
c.on_message = lambda cl, u, m: print(f"{dt.datetime.now():%H:%M:%S} RECEIVED {m.topic} {m.payload.decode()}", flush=True)
signal.signal(signal.SIGTERM, lambda *_: (c.disconnect(), sys.exit(0)))
c.connect("127.0.0.1", 18480); c.loop_forever()

"""127.0.0.1:18402로 들어온 연결을 127.0.0.1:18400(TLS 서버)로 그대로 넘기면서,
중간에서 '보이는 바이트'를 요약해 찍는다. 내 PC의 내 연결만 본다(수업 2-2·3-1).

    python peek_relay.py            # 한 연결만 중계하고 끝난다
"""
import socket, threading, sys

LISTEN, UPSTREAM = ("127.0.0.1", 18402), ("127.0.0.1", 18400)
seen = {"c2s": bytearray(), "s2c": bytearray()}

def pump(src, dst, key):
    try:
        while (b := src.recv(65536)):
            seen[key] += b
            dst.sendall(b)
    except OSError:
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except OSError: pass

def records(buf):
    """TLS 레코드 머리(형식 1바이트, 버전 2바이트, 길이 2바이트)만 읽는다."""
    names = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
    i, out = 0, []
    while i + 5 <= len(buf):
        t, ln = buf[i], int.from_bytes(buf[i+3:i+5], "big")
        out.append((names.get(t, t), ln, bytes(buf[i+5:i+5+min(ln, 16)]).hex()))
        i += 5 + ln
    return out

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(LISTEN); srv.listen(1)
print(f"listening {LISTEN} -> {UPSTREAM}", flush=True)
c, _ = srv.accept(); u = socket.create_connection(UPSTREAM)
ts = [threading.Thread(target=pump, args=(c, u, "c2s")), threading.Thread(target=pump, args=(u, c, "s2c"))]
[t.start() for t in ts]; [t.join() for t in ts]; c.close(); u.close(); srv.close()

needle = sys.argv[1].encode() if len(sys.argv) > 1 else b"FAKE-4111"
for key in ("c2s", "s2c"):
    print(f"\n[{key}] {len(seen[key])} bytes, '{needle.decode()}' 평문 포함? {needle in seen[key]}")
    for name, ln, head in records(seen[key]):
        print(f"  {name:<18} len={ln:<5} 앞 16바이트={head}")

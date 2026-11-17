#!/usr/bin/env python3
"""127.0.0.1에만 묶는 작은 TLS 서버 두 개 (한 프로세스, 스레드 두 개).
  18470: 옛 사슬(Root R1 → I1 → 리프)
  18471: 새 사슬(Root R2 → I2 → 리프)  — "서버 인증서가 새 루트로 옮겨 간 날"
Ctrl+C 또는 kill로 끈다.
"""
import os, socket, ssl, threading

HERE = os.path.dirname(os.path.abspath(__file__))


def serve(port, d):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(HERE, d, "chain.pem"), os.path.join(HERE, d, "leaf.key"))
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    print(f"listening 127.0.0.1:{port} chain={d}/chain.pem", flush=True)
    while True:
        c, _ = s.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(100); t.sendall(f"boiler-api ({d})\n".encode())
        except (ssl.SSLError, OSError):
            pass  # 클라이언트가 사슬을 거부하면 여기로 온다


ts = [threading.Thread(target=serve, args=(18470, "out/r1"), daemon=True),
      threading.Thread(target=serve, args=(18471, "out/r2"), daemon=True)]
for t in ts: t.start()
for t in ts: t.join()

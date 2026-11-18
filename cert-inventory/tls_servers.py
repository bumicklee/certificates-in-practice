"""수업 4-4·10-2 실습: 127.0.0.1에 TLS 서버 3개를 한 프로세스로 띄운다(18494·18495·18496)."""
import pathlib, socket, ssl, threading, time

F = pathlib.Path(__file__).parent / "fixtures/tls"
PORTS = {18494: "web-90d", 18495: "api-6d", 18496: "admin-forgotten"}


def serve(port, fn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(F / f"{fn}.crt", F / f"{fn}.key")
    s = socket.create_server(("127.0.0.1", port))
    while True:
        c, _ = s.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass


for p, fn in PORTS.items():
    threading.Thread(target=serve, args=(p, fn), daemon=True).start()
while True:
    time.sleep(3600)

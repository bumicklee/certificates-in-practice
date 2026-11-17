"""30편 실습: .well-known 파일을 HTTPS로 내보내는 작은 서버 (127.0.0.1에만).

  python server.py site 18492         # 올바른 세트
  python server.py site-broken 18493  # 틀린 세트
인증서는 공용 사설 CA의 리프(../private-ca/out/leaf.crt, SAN localhost)를 쓴다.
"""
import http.server, json, pathlib, ssl, sys

ROOT = pathlib.Path(sys.argv[1]).resolve()
PORT = int(sys.argv[2])
CA_OUT = pathlib.Path(__file__).parent.parent / "private-ca" / "out"
TYPES = {"assetlinks.json": "application/json", "apple-app-site-association": "application/json",
         "openid-configuration": "application/json", "jwks.json": "application/json",
         "webauthn": "application/json", "security.txt": "text/plain; charset=utf-8"}
over = ROOT / "_content_types.json"
if over.exists():
    TYPES.update(json.loads(over.read_text()))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/.well-known/change-password":       # 비밀번호 변경 페이지로 보내기만 한다
            self.send_response(302); self.send_header("Location", "/account/password"); self.end_headers(); return
        if path == "/security.txt":                      # 옛 위치는 .well-known으로
            self.send_response(301); self.send_header("Location", "/.well-known/security.txt"); self.end_headers(); return
        if path == "/account/password":
            body = b"<h1>change password (FAKE)</h1>"; ctype = "text/html; charset=utf-8"
        elif path.startswith("/.well-known/") and "/" not in path[len("/.well-known/"):]:
            name = path[len("/.well-known/"):]
            f = ROOT / ".well-known" / name
            if not f.is_file():
                self.send_error(404); return
            body = f.read_bytes(); ctype = TYPES.get(name, "application/octet-stream")
        else:
            self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CA_OUT / "chain.pem", CA_OUT / "leaf.key")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

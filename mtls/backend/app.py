"""아주 작은 백엔드. 앞단 프록시가 넘겨 준 X-Client-Cert(URL 인코딩된 PEM)에서 SAN URI를 읽어 인가한다.

환경 변수
  TRUSTED_PROXY  비우면 아무 데서 온 요청이든 헤더를 믿는다(취약). IP를 넣으면 그 IP에서 온 요청만 받는다.
"""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
from cryptography import x509

TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "")
# 인가 표: 경로별로 들어올 수 있는 서비스 신원(SPIFFE ID)
ALLOW = {
    "/orders":   {"spiffe://lab.example/orders"},
    "/payments": {"spiffe://lab.example/payments"},
}

def caller_ids(header_value: str) -> list[str]:
    cert = x509.load_pem_x509_certificate(unquote(header_value).encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return san.get_values_for_type(x509.UniformResourceIdentifier)

class H(BaseHTTPRequestHandler):
    def reply(self, code, **body):
        data = json.dumps(body, ensure_ascii=False).encode() + b"\n"
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        peer = self.client_address[0]
        if TRUSTED_PROXY and peer != TRUSTED_PROXY:
            return self.reply(403, error="not from trusted proxy", peer=peer)
        raw = self.headers.get("X-Client-Cert", "")
        if not raw:
            return self.reply(401, error="no client certificate")
        try:
            ids = caller_ids(raw)
        except Exception as e:  # 헤더가 깨졌으면 거절
            return self.reply(400, error=f"bad certificate header: {type(e).__name__}")
        allowed = ALLOW.get(self.path, set())
        if not any(i in allowed for i in ids):
            return self.reply(403, error="caller not allowed", caller=ids, path=self.path)
        return self.reply(200, ok=True, caller=ids, path=self.path, peer=peer)

    def log_message(self, fmt, *args):
        print(f"[backend] {self.client_address[0]} {fmt % args}", flush=True)

if __name__ == "__main__":
    print(f"[backend] TRUSTED_PROXY={TRUSTED_PROXY or '(none: trusts header from anywhere)'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

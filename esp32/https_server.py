#!/usr/bin/env python3
"""
https_server.py - PC-side lab server for cert-lab (course use only).

Serves, over TLS on the PC's LAN IP:
  GET /hello                  small text; used by demo 13-1
  GET /ota/latest.bin         the firmware image currently "offered" (switchable, see below); demo 13-3
  GET /ota/<name>.bin         any file from ota-images/

Three listeners show three different server certificates (demo 13-1):
  8443  good       leaf + intermediate from the lab chain, SAN = <PC_LAN_IP>
  8444  wrongname  lab-signed leaf whose SAN is another name   -> board: CN_MISMATCH
  8445  rogue      chain from an unknown root                  -> board: NOT_TRUSTED
Use --single good|wrongname|rogue to serve just one certificate on 8443 (cert switching).

Switch the OTA image while running: type one of these lines on stdin
  ota good      -> ota-images/ota-1.1.0.bin           (signed with the lab key, passes)
  ota bad       -> ota-images/ota-1.2.0-bad.bin       (signed, but its self-test fails: rollback)
  ota forged    -> ota-images/ota-1.1.0-forged.bin    (signed with ANOTHER key: rejected)
  ota none      -> 404

TLS handshake failures from clients are printed, so you can see the server's side of each failure.
"""
import argparse
import http.server
import socket
import socketserver
import ssl
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKI = HERE / "demo-pki"
OTA_DIR = HERE / "ota-images"

CERTS = {
    "good":      (PKI / "server" / "server-chain.crt",        PKI / "server" / "server.key"),
    "wrongname": (PKI / "wrongname" / "wrongname-chain.crt",  PKI / "wrongname" / "wrongname.key"),
    "rogue":     (PKI / "rogue" / "rogue-server-chain.crt",   PKI / "rogue" / "rogue-server.key"),
}
OTA_CHOICES = {
    "good": "ota-1.1.0.bin",
    "bad": "ota-1.2.0-bad.bin",
    "forged": "ota-1.1.0-forged.bin",
    "none": None,
}
state = {"ota": "good"}
state_lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "cert-lab"
    label = "?"

    def setup(self):
        super().setup()

    def handle(self):
        # TLS handshake happens here (in the worker thread) so a failed handshake only costs one connection.
        try:
            self.request.do_handshake()
        except (ssl.SSLError, OSError) as e:
            print(f"[{self.server.label}] TLS handshake FAILED from {self.client_address[0]}: {e}", flush=True)
            return
        print(f"[{self.server.label}] TLS ok from {self.client_address[0]} "
              f"({self.request.version()}, {self.request.cipher()[0]})", flush=True)
        super().handle()

    def log_message(self, fmt, *args):
        print(f"[{self.server.label}] {self.client_address[0]} {fmt % args}", flush=True)

    def _send(self, code, body, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hello":
            self._send(200, f"hello from cert-lab server [{self.server.label}]\n".encode())
            return
        if self.path.startswith("/ota/"):
            name = self.path[len("/ota/"):]
            if name == "latest.bin":
                with state_lock:
                    name = OTA_CHOICES.get(state["ota"])
                if name is None:
                    self._send(404, b"no image offered\n")
                    return
            f = (OTA_DIR / name).resolve()
            if OTA_DIR.resolve() not in f.parents or not f.is_file():
                self._send(404, b"not found\n")
                return
            data = f.read_bytes()
            print(f"[{self.server.label}] OTA serving {f.name} ({len(data)} bytes)", flush=True)
            self._send(200, data, "application/octet-stream")
            return
        self._send(404, b"not found\n")


class TLSServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, label, ctx):
        self.label = label
        self.ctx = ctx
        super().__init__(addr, Handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(15)
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


def make_ctx(kind):
    crt, key = CERTS[kind]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(crt), str(key))
    return ctx


def stdin_loop():
    for line in sys.stdin:
        parts = line.split()
        if len(parts) == 2 and parts[0] == "ota" and parts[1] in OTA_CHOICES:
            with state_lock:
                state["ota"] = parts[1]
            print(f"[control] latest.bin now offers: {parts[1]} ({OTA_CHOICES[parts[1]]})", flush=True)
        elif parts:
            print("[control] usage: ota good|bad|forged|none", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default=(PKI / "embed" / "LAN_IP.txt").read_text().strip()
                    if (PKI / "embed" / "LAN_IP.txt").exists() else None,
                    help="LAN IP to bind (default: the IP given to make_pki.sh)")
    ap.add_argument("--single", choices=sorted(CERTS), help="serve only this certificate, on --port")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--ota", choices=sorted(OTA_CHOICES), default="good", help="image offered as /ota/latest.bin")
    args = ap.parse_args()
    if not args.bind:
        sys.exit("run ./make_pki.sh <PC_LAN_IP> first (or pass --bind)")
    state["ota"] = args.ota

    listeners = [("good", args.port)] if not args.single else [(args.single, args.port)]
    if not args.single:
        listeners = [("good", 8443), ("wrongname", 8444), ("rogue", 8445)]
    for kind, port in listeners:
        srv = TLSServer((args.bind, port), kind, make_ctx(kind))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[server] {kind:9s} https://{args.bind}:{port}/hello", flush=True)
    print(f"[server] OTA offered as /ota/latest.bin: {state['ota']}   (type 'ota good|bad|forged|none' to switch)", flush=True)
    try:
        stdin_loop()
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

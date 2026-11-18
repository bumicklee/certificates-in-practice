"""수업 6-1: Python httpx mTLS 클라이언트. 다섯 경우를 차례로 부른다.

  ../.venv/bin/python clients/client.py [https://localhost:18440/orders]
"""
import ssl, sys
from pathlib import Path
import re
import httpx

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parent / "private-ca" / "out" / "root.crt"   # 서버 인증서를 믿을 루트
URL = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:18440/orders"

CASES = [
    ("정상(orders)",        "ok"),
    ("인증서 없음",          None),
    ("다른 CA",             "otherca"),
    ("만료",                "expired"),
    ("다른 신원(payments)",  "payments"),
]

def ctx_for(name):
    ctx = ssl.create_default_context(cafile=str(ROOT))      # 서버 검증은 늘 켠다
    if name:
        d = HERE / "out" / name
        ctx.load_cert_chain(d / "chain.pem", d / "client.key")  # 리프+중간, 개인키
    return ctx

for label, name in CASES:
    try:
        with httpx.Client(verify=ctx_for(name), timeout=5) as c:
            r = c.get(URL)
        m = re.search(r"<title>(.*?)</title>", r.text)
        body = m.group(1) if m else r.text.strip()
        print(f"{label:<14} → HTTP {r.status_code} {body}")
    except Exception as e:
        print(f"{label:<14} → {type(e).__name__}: {e}")

# 덤: 서버 이름 확인. 인증서 SAN에 없는 이름(api.lab.example)으로 접속하면 클라이언트가 끊는다
try:
    with httpx.Client(verify=ctx_for("ok"), timeout=5) as c:
        c.get(URL, extensions={"sni_hostname": "api.lab.example"})
except Exception as e:
    print(f"{'서버 이름 불일치':<14} → {type(e).__name__}: {e}")

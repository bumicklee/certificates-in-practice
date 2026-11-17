"""10·32편 실습: "내 인증서 만료 목록" 한 표로 모으기.

  python inventory.py --endpoint 127.0.0.1:18494 ... --pem-dir DIR --kube-pki DIR --k8s-secrets DIR [--warn 30] [--prom out.prom]

- 엔드포인트: TLS로 붙어 서버가 내는 리프를 읽는다(신뢰 검사는 하지 않는다. 목록이 목적이다).
- PEM 폴더: *.crt, *.pem 안의 인증서를 모두 읽는다(묶음 파일은 한 장씩).
- kubeadm pki: *.crt와 *.conf 안의 client-certificate-data.
- 쿠버네티스 비밀값 YAML: data.tls.crt.
"""
import argparse, base64, datetime as dt, pathlib, re, socket, ssl, sys

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = dt.datetime.now(dt.timezone.utc)
rows = []


def add(source, where, c):
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        bc = False
    try:
        ekus = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        kind = "code-sign" if ExtendedKeyUsageOID.CODE_SIGNING in ekus else "server" if ExtendedKeyUsageOID.SERVER_AUTH in ekus else "leaf"
    except x509.ExtensionNotFound:
        kind = "leaf"
    life = (c.not_valid_after_utc - c.not_valid_before_utc).days
    rows.append({"days": (c.not_valid_after_utc - NOW).total_seconds() / 86400, "source": source, "where": where,
                 "cn": cn[0].value if cn else "-", "kind": "CA" if bc else kind, "life": life,
                 "not_after": c.not_valid_after_utc.strftime("%Y-%m-%d")})


def pem_certs(data: bytes):
    return [x509.load_pem_x509_certificate(m) for m in
            re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", data, re.S)]


ap = argparse.ArgumentParser()
ap.add_argument("--endpoint", action="append", default=[])
ap.add_argument("--pem-dir"); ap.add_argument("--kube-pki"); ap.add_argument("--k8s-secrets")
ap.add_argument("--warn", type=int, default=30); ap.add_argument("--prom")
a = ap.parse_args()

for ep in a.endpoint:
    host, port = ep.rsplit(":", 1)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=3) as s, ctx.wrap_socket(s) as t:
            add("tls", ep, x509.load_der_x509_certificate(t.getpeercert(binary_form=True)))
    except OSError as e:
        rows.append({"days": -1e9, "source": "tls", "where": ep, "cn": f"접속 실패: {e.__class__.__name__}",
                     "kind": "-", "life": 0, "not_after": "-"})

if a.pem_dir:
    for f in sorted(pathlib.Path(a.pem_dir).rglob("*")):
        if f.suffix in (".crt", ".pem"):
            for i, c in enumerate(pem_certs(f.read_bytes())):
                add("pem", f.name + (f"#{i+1}" if i or f.suffix == ".pem" else ""), c)

if a.kube_pki:
    base = pathlib.Path(a.kube_pki)
    for f in sorted(base.rglob("*.crt")):
        add("kubeadm", str(f.relative_to(base)), pem_certs(f.read_bytes())[0])
    for f in sorted(base.glob("*.conf")):
        for b in re.findall(r"client-certificate-data:\s*(\S+)", f.read_text()):
            add("kubeadm", f.name, pem_certs(base64.b64decode(b))[0])

if a.k8s_secrets:
    for f in sorted(pathlib.Path(a.k8s_secrets).glob("*.yaml")):
        t = f.read_text()
        ns = re.search(r"namespace:\s*(\S+)", t); nm = re.search(r"name:\s*(\S+)", t)
        for b in re.findall(r"tls\.crt:\s*(\S+)", t):
            add("k8s-secret", f"{ns.group(1) if ns else '-'}/{nm.group(1) if nm else f.stem}", pem_certs(base64.b64decode(b))[0])

rows.sort(key=lambda r: r["days"])
print(f"기준 시각 {NOW:%Y-%m-%d %H:%M} UTC, 경고 기준 {a.warn}일\n")
print(f"{'상태':<8}{'남은 일':>8}  {'만료일':<11} {'수명':>6}  {'출처':<11}{'위치':<34}{'종류':<10}CN")
for r in rows:
    d = r["days"]
    st = "ERROR" if d < -1e8 else "EXPIRED" if d < 0 else "WARN" if d < a.warn else "ok"
    dd = "-" if d < -1e8 else f"{d:.0f}"
    print(f"{st:<8}{dd:>8}  {r['not_after']:<11} {str(r['life'])+'d':>6}  {r['source']:<11}{r['where']:<34}{r['kind']:<10}{r['cn']}")
bad = [r for r in rows if r["days"] < a.warn]
print(f"\n합계 {len(rows)}장 / {a.warn}일 안에 만료(또는 이미 만료) {len(bad)}장")
if a.prom:  # Prometheus node_exporter textfile 수집기 형식
    with open(a.prom, "w") as fp:
        fp.write("# HELP lab_cert_expiry_days Days until certificate notAfter\n# TYPE lab_cert_expiry_days gauge\n")
        for r in rows:
            if r["days"] > -1e8:
                fp.write(f'lab_cert_expiry_days{{source="{r["source"]}",where="{r["where"]}",cn="{r["cn"]}"}} {r["days"]:.1f}\n')
sys.exit(1 if bad else 0)

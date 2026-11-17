"""10·32편 실습 재료: 수명이 제각각인 가짜 인증서들을 만든다(모두 실습 전용, 가짜 이름).

fixtures/
  tls/            로컬 TLS 서버 3개용 인증서·키 (lab-ca가 서명)
  pem/            웹 밖 인증서들: SAML IdP 서명, APNs 흉내, 코드 서명, 기기 루트 묶음
  kube-pki/       kubeadm 모양의 pki 폴더 (CA 10년, 리프 1년) + admin.conf
  k8s-secrets/    kubernetes.io/tls 비밀값 YAML
'키는 fixtures/**/*.key 에만 있고 출력하지 않는다.'
"""
import base64, datetime as dt, pathlib, shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = pathlib.Path(__file__).parent / "fixtures"
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
D = lambda n: dt.timedelta(days=n)


def name(cn, o="FAKE Lab"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(cn, issued_days_ago, lifetime_days, issuer=None, ca=False, eku=None, san=None, o="FAKE Lab"):
    key = ec.generate_private_key(ec.SECP256R1())
    nb = NOW - D(issued_days_ago)
    subj = name(cn, o)
    b = (x509.CertificateBuilder().subject_name(subj)
         .issuer_name(issuer[0].subject if issuer else subj)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(nb + D(lifetime_days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    c = b.sign(issuer[1] if issuer else key, hashes.SHA256())
    return c, key


def save(path, c, key=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        kp = path.with_suffix(".key")
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        kp.chmod(0o600)


shutil.rmtree(OUT, ignore_errors=True)

# (a) 로컬 TLS 엔드포인트 3개
labca = cert("FAKE Inventory Lab CA", 30, 3650, ca=True)
save(OUT / "tls/lab-ca.crt", *labca)
for fn, cn, ago, life in [("web-90d", "shop.lab.example", 10, 90),       # 80일 남음
                          ("api-6d", "api.lab.example", 2, 6),           # 4일 남음(단기 인증서)
                          ("admin-forgotten", "admin.lab.example", 375, 398)]:  # 23일 남음
    save(OUT / f"tls/{fn}.crt", *cert(cn, ago, life, issuer=labca, san=[cn],
                                      eku=[ExtendedKeyUsageOID.SERVER_AUTH]))

# (b) 웹 밖 인증서들
save(OUT / "pem/saml-idp-signing.crt", cert("FAKE IdP SAML Signing", 1083, 1095, o="FAKE IdP")[0])    # 12일 남음
save(OUT / "pem/apns-like-push.crt", cert("Apple Push Services: example.lab.shop (FAKE)", 340, 365,
                                         o="FAKE Push")[0])                                          # 25일 남음
save(OUT / "pem/code-signing.crt", cert("FAKE Shop Code Signing", 30, 1095,
                                        eku=[ExtendedKeyUsageOID.CODE_SIGNING])[0])
# 기기 펌웨어에 넣은 루트 묶음(PEM 여러 장): 하나는 이미 만료, 하나는 2년 남음
r1 = cert("FAKE Device Root R1", 3660, 3650, ca=True)[0]
r2 = cert("FAKE Device Root R2", 2900, 3650, ca=True)[0]
(OUT / "pem").mkdir(exist_ok=True)
(OUT / "pem/device-root-bundle.pem").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (r1, r2)))

# (c) kubeadm 모양: CA 10년, 리프 1년. 클러스터를 335일 전에 만들고 한 번도 업그레이드하지 않은 상태
AGO = 335
kca = cert("kubernetes", AGO, 3650, ca=True); save(OUT / "kube-pki/ca.crt", *kca)
fca = cert("front-proxy-ca", AGO, 3650, ca=True); save(OUT / "kube-pki/front-proxy-ca.crt", *fca)
eca = cert("etcd-ca", AGO, 3650, ca=True); save(OUT / "kube-pki/etcd/ca.crt", *eca)
for p, cn, iss in [("apiserver", "kube-apiserver", kca), ("apiserver-kubelet-client", "kube-apiserver-kubelet-client", kca),
                   ("front-proxy-client", "front-proxy-client", fca), ("apiserver-etcd-client", "kube-apiserver-etcd-client", eca),
                   ("etcd/server", "fake-cp-1", eca), ("etcd/peer", "fake-cp-1", eca),
                   ("etcd/healthcheck-client", "kube-etcd-healthcheck-client", eca)]:
    save(OUT / f"kube-pki/{p}.crt", *cert(cn, AGO, 365, issuer=iss))
adm, _ = cert("kubernetes-admin", AGO, 365, issuer=kca, o="kubeadm:cluster-admins")
b64 = base64.b64encode(adm.public_bytes(serialization.Encoding.PEM)).decode()
(OUT / "kube-pki/admin.conf").write_text(
    "apiVersion: v1\nkind: Config\nusers:\n- name: kubernetes-admin\n  user:\n"
    f"    client-certificate-data: {b64}\n    client-key-data: FAKE-REDACTED\n")

# (d) 쿠버네티스 TLS 비밀값
ing, _ = cert("orders.lab.example", 50, 90, issuer=labca, san=["orders.lab.example"])
(OUT / "k8s-secrets").mkdir(exist_ok=True)
(OUT / "k8s-secrets/orders-tls.yaml").write_text(
    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: orders-tls\n  namespace: shop\ntype: kubernetes.io/tls\ndata:\n"
    f"  tls.crt: {base64.b64encode(ing.public_bytes(serialization.Encoding.PEM)).decode()}\n  tls.key: FAKE-REDACTED\n")
print("만듦:", OUT)

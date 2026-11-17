"""step ca init이 만든 ca.json을 고친다: 오프라인 루트/우리 중간 CA를 쓰고, 수명을 짧게."""
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["root"] = "/home/step/online/root.crt"
c["crt"] = "/home/step/online/inter.crt"
c["key"] = "/home/step/online/inter.key"
c.setdefault("authority", {})["claims"] = {
    "defaultTLSCertDuration": "24h", "maxTLSCertDuration": "72h", "minTLSCertDuration": "5m",
    "enableSSHCA": True,
    "defaultUserSSHCertDuration": "4h", "maxUserSSHCertDuration": "8h",
}
json.dump(c, open(p, "w"), indent=2)
print("patched", p)

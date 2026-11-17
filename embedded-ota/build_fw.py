#!/usr/bin/env python3
"""가짜 펌웨어 이미지를 만들고 openssl(ECDSA P-256 / SHA-256)로 서명한다.

  build_fw.py 1.1.0 --sv 2 --bundle out/r1/root.crt out/r2/root.crt
  build_fw.py 1.2.0 --sv 2 --bundle ... --selftest fail      # 부팅 후 자체 시험에 실패하는 이미지
  build_fw.py 1.1.0 --sv 2 --bundle ... --key out/wrong/wrong.key --name forged-key  # 다른 키로 서명

만들어지는 것 (out/fw/)
  <name>.bin            이미지 본문: 가짜 코드 + 루트 묶음(PEM) + 자체 시험 표시
  <name>.payload        서명 대상(정렬·압축한 매니페스트 JSON, signature 칸 없음)
  <name>.sig.der        openssl dgst -sha256 -sign 결과(DER ECDSA)
  <name>.manifest.json  payload 칸 + signature(base64)
"""
import argparse, base64, datetime, hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--sv", type=int, required=True, help="security_version (롤백 방지 하한과 비교)")
    ap.add_argument("--bundle", nargs="+", required=True, help="이미지에 넣을 루트 인증서 PEM들")
    ap.add_argument("--selftest", choices=["ok", "fail"], default="ok")
    ap.add_argument("--key", default=os.path.join(HERE, "out/ota/ota_sign.key"))
    ap.add_argument("--name", default=None)
    ap.add_argument("--build-time", default=None, help="빌드 시각(기기 시각 하한). 기본은 지금")
    a = ap.parse_args()

    name = a.name or f"boiler-{a.version}"
    outd = os.path.join(HERE, "out/fw"); os.makedirs(outd, exist_ok=True)
    bundle = b"".join(open(p, "rb").read() for p in a.bundle)
    body = (f"FAKE-FIRMWARE boiler-ctl {a.version}\n".encode()
            + hashlib.sha256(f"code-{a.version}".encode()).digest() * 64   # 2KB 가짜 코드
            + b"\n-----CA-BUNDLE-----\n" + bundle + b"-----END-CA-BUNDLE-----\n"
            + f"-----SELFTEST:{a.selftest}-----\n".encode())
    open(os.path.join(outd, name + ".bin"), "wb").write(body)

    manifest = {
        "product": "boiler-ctl",
        "version": a.version,
        "security_version": a.sv,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "build_time": a.build_time or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    pfile = os.path.join(outd, name + ".payload"); open(pfile, "wb").write(payload)
    sfile = os.path.join(outd, name + ".sig.der")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.key, "-out", sfile, pfile], check=True)
    manifest["signature"] = base64.b64encode(open(sfile, "rb").read()).decode()
    json.dump(manifest, open(os.path.join(outd, name + ".manifest.json"), "w"), indent=2)
    print(f"built {name}: version={a.version} security_version={a.sv} size={len(body)} "
          f"sha256={manifest['sha256'][:16]}… roots={bundle.count(b'BEGIN CERTIFICATE')} selftest={a.selftest}")


if __name__ == "__main__":
    sys.exit(main())

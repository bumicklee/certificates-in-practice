#!/usr/bin/env python3
"""수업 9-2·9-3: 받아 둔 Google 증명 폐기 목록(google/status.json)의 모양을 본다. 일련번호는 줄여서 보인다.
  curl -s -D google/status.headers -o google/status.json https://android.googleapis.com/attestation/status
  ../../.venv/bin/python -I show_status.py
"""
import collections, json, os
HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(f"{HERE}/google/status.json"))
e = d["entries"]
print("top-level keys:", list(d))
print("entries:", len(e))
print("status:", dict(collections.Counter(v["status"] for v in e.values())))
print("reason:", dict(collections.Counter(v.get("reason", "(none)") for v in e.values())))
print("fields used:", dict(collections.Counter(k for v in e.values() for k in v)))
lens = collections.Counter(len(k) for k in e)
print("serial hex length (chars):", dict(sorted(lens.items())))
k, v = next(iter(e.items()))
print("example:", json.dumps({k[:6] + "…" + k[-4:]: v}, ensure_ascii=False))
for line in open(f"{HERE}/google/status.headers"):
    if line.lower().startswith(("cache-control", "date", "content-type")):
        print("header:", line.strip())

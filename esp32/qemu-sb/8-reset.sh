#!/usr/bin/env bash
# 8. Start over: delete the QEMU eFuse files (a real chip has no such button).
. "$(dirname "$0")/lib.sh"
for f in efuse-sb.bin efuse-fe.bin; do
  if [ -f "$OUT/$f" ]; then rm "$OUT/$f"; echo "removed out/$f"; fi
done
echo "next: ./4-sb-run.sh  (first boot again on a blank eFuse file)"

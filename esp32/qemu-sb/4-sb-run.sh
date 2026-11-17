#!/usr/bin/env bash
# 4. Boot the Secure Boot build in QEMU. First boot on a blank eFuse file burns the key digest.
. "$(dirname "$0")/lib.sh"
[ -f "$OUT/efuse-sb.bin" ] || { new_efuse "$OUT/efuse-sb.bin"; echo "new blank eFuse file: out/efuse-sb.bin"; }
make_flash "$OUT/sb" "$OUT/flash-sb.bin"
run_qemu "$OUT/flash-sb.bin" "$OUT/efuse-sb.bin" "${SECS:-8}" "$OUT/logs/${LOG:-4-sb-run}.log"
cat "$OUT/logs/${LOG:-4-sb-run}.log"

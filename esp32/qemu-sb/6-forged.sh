#!/usr/bin/env bash
# 6. Same bootloader, but the APP is signed with the other practice key. Boot on the SAME eFuse file.
#    ./6-forged.sh bootloader  -> instead, the BOOTLOADER is signed with the other key (the ROM's gate).
. "$(dirname "$0")/lib.sh"
[ -f "$OUT/efuse-sb.bin" ] || { echo "run ./4-sb-run.sh first (eFuse file has no key digest yet)"; exit 1; }
build sb-other sdkconfig.defaults sdkconfig.sb sdkconfig.sb-other >/dev/null 2>&1 || { echo build failed; exit 1; }
if [ "${1:-app}" = bootloader ]; then
  make_flash "$OUT/sb-other" "$OUT/flash-forged-bl.bin" "$OUT/sb/qemu_sb.bin"
  echo "flash: bootloader from out/sb-other (other_key), table+app from out/sb (sb_key)"
  run_qemu "$OUT/flash-forged-bl.bin" "$OUT/efuse-sb.bin" "${SECS:-4}" "$OUT/logs/6-forged-bootloader.log"
  cat "$OUT/logs/6-forged-bootloader.log"
else
  make_flash "$OUT/sb" "$OUT/flash-forged.bin" "$OUT/sb-other/qemu_sb.bin"
  echo "flash: bootloader+table from out/sb (sb_key), app from out/sb-other (other_key)"
  run_qemu "$OUT/flash-forged.bin" "$OUT/efuse-sb.bin" "${SECS:-8}" "$OUT/logs/6-forged.log"
  cat "$OUT/logs/6-forged.log"
fi

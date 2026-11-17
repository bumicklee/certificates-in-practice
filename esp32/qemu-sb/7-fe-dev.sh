#!/usr/bin/env bash
# 7. Second variant: flash encryption, Development mode, on its OWN blank eFuse file (out/efuse-fe.bin).
. "$(dirname "$0")/lib.sh"
build fe sdkconfig.defaults sdkconfig.fe >/dev/null 2>&1 || { echo build failed; exit 1; }
grep -E '^CONFIG_SECURE_FLASH_(ENC_ENABLED|ENCRYPTION_MODE_DEVELOPMENT)=' "$OUT/fe/sdkconfig"
new_efuse "$OUT/efuse-fe.bin"; echo "new blank eFuse file: out/efuse-fe.bin"
make_flash "$OUT/fe" "$OUT/flash-fe.bin"
run_qemu "$OUT/flash-fe.bin" "$OUT/efuse-fe.bin" "${SECS:-20}" "$OUT/logs/7-fe-dev.log"
cat "$OUT/logs/7-fe-dev.log"
echo "--- eFuse summary (out/efuse-fe.bin, flash-encryption lines)"
efuse "$OUT/efuse-fe.bin" summary 2>&1 | grep -E -A3 '^SPI_BOOT_CRYPT_CNT|^KEY_PURPOSE_0 |^BLOCK_KEY0' | grep -vE '^--$|Key0 or user data'
echo "--- the app's text in the flash file, read from outside (as a chip reader would)"
printf 'before (out/fe/qemu_sb.bin, plain build output): %s match(es)\n' "$(LC_ALL=C grep -c -a 'course demo' "$OUT/fe/qemu_sb.bin" || true)"
printf 'after  (out/flash-fe.bin, flash after first boot): %s match(es)\n' "$(LC_ALL=C grep -c -a 'course demo' "$OUT/flash-fe.bin" || true)"

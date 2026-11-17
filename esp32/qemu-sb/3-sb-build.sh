#!/usr/bin/env bash
# 3. Build with Secure Boot v2 on: signed bootloader + signed app (key: keys/sb_key.pem)
. "$(dirname "$0")/lib.sh"
echo "--- sdkconfig (secure boot lines)"
build sb sdkconfig.defaults sdkconfig.sb > "$OUT/logs/3-sb-build.log" 2>&1 || { tail -30 "$OUT/logs/3-sb-build.log"; exit 1; }
grep -E '^CONFIG_(SECURE_BOOT|SECURE_BOOT_V2_ENABLED|SECURE_SIGNED_APPS_RSA_SCHEME|SECURE_BOOT_SIGNING_KEY|SECURE_INSECURE_ALLOW_DL_MODE)=' "$OUT/sb/sdkconfig"
echo "--- build log (signing lines; full log: out/logs/3-sb-build.log)"
grep -E 'signing key|Signed [0-9]+ bytes|Generated signed binary|Bootloader binary size|Project build complete' "$OUT/logs/3-sb-build.log" \
  | sed -e "s#$QSB#…/qemu-sb#g" -e 's#^\[[0-9/]*\] ##'

#!/usr/bin/env bash
# 2. Two PRACTICE signing keys (QEMU only). Key contents are never printed.
#    ESP32-C3 Secure Boot v2 knows only RSA-3072 (the course board ESP32-C5 uses ECDSA P-256).
. "$(dirname "$0")/lib.sh"
mkdir -p "$KEYS"; chmod 700 "$KEYS"
for k in sb_key other_key; do
  if [ -f "$KEYS/$k.pem" ]; then echo "keys/$k.pem already exists (kept)"; continue; fi
  espsecure.py generate_signing_key --version 2 --scheme rsa3072 "$KEYS/$k.pem" | sed "s#$QSB/##"
  chmod 600 "$KEYS/$k.pem"
done
# public-key digests (what the bootloader will burn into eFuse) - public values, safe to show
for k in sb_key other_key; do
  espsecure.py digest_sbv2_public_key --keyfile "$KEYS/$k.pem" --output "$OUT/$k.digest" >/dev/null
  printf '%-10s public key digest: %s\n' "$k" "$(xxd -p -c 64 "$OUT/$k.digest")"
done

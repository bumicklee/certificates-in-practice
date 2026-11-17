#!/usr/bin/env bash
# build_all.sh - build every cert-lab mode into build/<mode>/ and collect OTA images in ota-images/.
# Needs: ESP-IDF v5.5 exported (. ~/esp/esp-idf-v5.5/export.sh) and ./make_pki.sh already run.
# Optional env: WIFI_SSID, WIFI_PASS (kept only in build/_local.defaults, never committed), MODES="a b"
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$HERE/cert-lab"
[[ -f "$HERE/demo-pki/embed/LAN_IP.txt" ]] || { echo "run ./make_pki.sh <PC_LAN_IP> first" >&2; exit 1; }
command -v idf.py >/dev/null || { echo "export ESP-IDF first" >&2; exit 1; }

LAN_IP="$(cat "$HERE/demo-pki/embed/LAN_IP.txt")"
mkdir -p "$HERE/build" "$HERE/ota-images"
LOCAL="$HERE/build/_local.defaults"
{
  echo "CONFIG_LAB_SERVER_IP=\"$LAN_IP\""
  echo "CONFIG_LAB_WIFI_SSID=\"${WIFI_SSID:-CHANGE_ME_SSID}\""
  echo "CONFIG_LAB_WIFI_PASSWORD=\"${WIFI_PASS:-CHANGE_ME_PASSWORD}\""
} > "$LOCAL"

ALL="tls-check tls-check-nosntp mqtt-mtls mqtt-nocert mqtt-expired ota-1.0.0 ota-1.1.0 ota-1.2.0-bad ota-1.1.0-forged"
cd "$PROJ"
for m in ${MODES:-$ALL}; do
  B="$HERE/build/$m"
  echo "=== building $m ==="
  idf.py -B "$B" -D IDF_TARGET=esp32c5 -D SDKCONFIG="$B/sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$PROJ/sdkconfig.defaults;$PROJ/modes/$m.defaults;$LOCAL" build > "$B.log" 2>&1 \
    || { echo "BUILD FAILED: $m (see $B.log)"; tail -30 "$B.log"; exit 1; }
  # signed app image = <build>/cert-lab-signed.bin (when signing is on), else cert-lab.bin
  BIN="$B/cert-lab.bin"; [[ -f "$B/cert-lab-signed.bin" ]] && BIN="$B/cert-lab-signed.bin"
  echo "    $(basename "$BIN"): $(stat -f%z "$BIN" 2>/dev/null || stat -c%s "$BIN") bytes"
  case "$m" in
    ota-1.1.0|ota-1.2.0-bad|ota-1.1.0-forged) cp "$BIN" "$HERE/ota-images/$m.bin" ;;
  esac
done

#!/usr/bin/env bash
# run_broker.sh - Mosquitto (Docker) requiring client certificates on 8883, published on the LAN IP only.
# usage: ./run_broker.sh [LAN_IP]      (default: IP given to make_pki.sh). Ctrl-C stops and removes it.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IP="${1:-$(cat "$HERE/demo-pki/embed/LAN_IP.txt")}"
docker rm -f certlab-mosquitto >/dev/null 2>&1 || true
echo "[broker] mqtts on $IP:8883 (mTLS required)"
exec docker run --rm --name certlab-mosquitto \
  -p "$IP:8883:8883" \
  -v "$HERE/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro" \
  -v "$HERE/demo-pki:/pki:ro" \
  eclipse-mosquitto:2

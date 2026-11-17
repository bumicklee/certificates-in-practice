#!/usr/bin/env bash
# broker_check.sh - test the broker from the PC BEFORE using the board (needs mosquitto_pub: brew install mosquitto)
#   ./broker_check.sh with-cert   -> must succeed
#   ./broker_check.sh no-cert     -> must be refused (broker log: peer did not return a certificate)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; PKI="$HERE/demo-pki"; IP="$(cat "$PKI/embed/LAN_IP.txt")"
case "${1:-}" in
  with-cert) mosquitto_pub -h "$IP" -p 8883 --cafile "$PKI/root/lab-root.crt" \
      --cert "$PKI/device/dev-001-chain.crt" --key "$PKI/device/dev-001.key" -t certlab/test -m ok -d ;;
  no-cert)   mosquitto_pub -h "$IP" -p 8883 --cafile "$PKI/root/lab-root.crt" -t certlab/test -m ok -d || true ;;
  *) echo "usage: $0 with-cert|no-cert"; exit 1 ;;
esac

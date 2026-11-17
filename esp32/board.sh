#!/usr/bin/env bash
# board.sh - the ONLY place that touches the board. Tested with ESP32-C5 v1.0, 8MB flash. Use BAUD=115200 on a CP210x/CH340 adapter: 460800 gave "Invalid head of packet".
#
#   PORT=/dev/cu.usbserial-XXXX ./board.sh backup  [name]      read the whole flash into backups/<name>.bin  (do this FIRST)
#   PORT=...                    ./board.sh flash   <mode>      write build/<mode> (bootloader+table+otadata+app)
#   PORT=...                    ./board.sh monitor <mode>      serial monitor with symbol decoding
#   PORT=...                    ./board.sh restore <file.bin>  write a full-flash backup back to offset 0
#
# No eFuse is ever written. `backup` only reads. Close any other program using the port first.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${PORT:?set PORT, e.g. PORT=/dev/cu.usbserial-XXXX (not the port another program is using)}"
CHIP=esp32c5
BAUD="${BAUD:-460800}"
cmd="${1:-}"; arg="${2:-}"

case "$cmd" in
  backup)
    name="${arg:-board-before-certlab-$(date +%Y%m%d-%H%M%S)}"
    mkdir -p "$HERE/backups"
    # 1) read-only identification (shows flash size and chip revision)
    esptool.py --chip "$CHIP" -p "$PORT" flash_id | tee "$HERE/backups/$name.flash_id.txt"
    size="${FLASH_SIZE:-}"
    [[ -n "$size" ]] || { echo "Set FLASH_SIZE from the 'Detected flash size' line above, e.g. FLASH_SIZE=0x400000 (4MB), 0x800000 (8MB), 0x1000000 (16MB), then rerun."; exit 2; }
    # 2) full flash dump = bootloader + partition table + the current firmware + NVS (contains that firmware's Wi-Fi/user data: keep private)
    esptool.py --chip "$CHIP" -p "$PORT" -b "$BAUD" read_flash 0 "$size" "$HERE/backups/$name.bin"
    shasum -a 256 "$HERE/backups/$name.bin" | tee "$HERE/backups/$name.sha256"
    echo "Verify the dump by reading it twice and comparing hashes before flashing anything."
    ;;
  flash)
    [[ -d "$HERE/build/$arg" ]] || { echo "no build/$arg (run build_all.sh)"; exit 1; }
    ( cd "$HERE/build/$arg" && esptool.py --chip "$CHIP" -p "$PORT" -b "$BAUD" write_flash @flash_args )
    ;;
  monitor)
    python -m esp_idf_monitor -p "$PORT" -b 115200 --toolchain-prefix riscv32-esp-elf- --target "$CHIP" \
      "$HERE/build/$arg/cert-lab.elf"
    ;;
  restore)
    [[ -f "$arg" ]] || { echo "usage: PORT=... $0 restore backups/<file>.bin"; exit 1; }
    esptool.py --chip "$CHIP" -p "$PORT" -b "$BAUD" write_flash 0 "$arg"
    ;;
  *) sed -n 2,10p "$0"; exit 1 ;;
esac

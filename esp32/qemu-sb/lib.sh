# shellcheck shell=bash
# Shared helpers for the QEMU Secure Boot / flash encryption demo. Sourced by the numbered scripts.
# QEMU ONLY: nothing here opens a serial port; espefuse talks to QEMU over socket://localhost:$QSB_PORT.
set -eo pipefail
QSB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$QSB/app"; OUT="$QSB/out"; KEYS="$QSB/keys"
QSB_PORT="${QSB_PORT:-5555}"
mkdir -p "$OUT/logs"

if ! command -v idf.py >/dev/null 2>&1; then
  export PATH="$HOME/.espressif/python_env/idf5.5_py3.14_env/bin:$PATH"
  export IDF_PYTHON_ENV_PATH="$HOME/.espressif/python_env/idf5.5_py3.14_env"
  # shellcheck disable=SC1090
  . "$HOME/esp/esp-idf-v5.5/export.sh" >/dev/null 2>&1
fi

# build <name> <defaults files...>  -> $OUT/<name>/ (own sdkconfig)
build() {
  local name="$1"; shift
  local defs=""; for d in "$@"; do defs+="${defs:+;}$APP/$d"; done
  idf.py -C "$APP" -B "$OUT/$name" -D SDKCONFIG="$OUT/$name/sdkconfig" \
         -D SDKCONFIG_DEFAULTS="$defs" -D IDF_TARGET=esp32c3 build
}

# new_efuse <file> : fresh eFuse file with the same defaults `idf.py qemu` writes (blank chip)
new_efuse() {
  python - "$1" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ['IDF_PATH'], 'tools'))
from idf_py_actions.qemu_ext import QEMU_TARGETS
open(sys.argv[1], 'wb').write(QEMU_TARGETS['esp32c3'].default_efuse)
PY
}

# make_flash <build dir> <out flash file> [app bin to use instead of the build's own]
make_flash() {
  local b="$1" f="$2" app="${3:-}"
  local args="$b/flash_args"
  if [ -n "$app" ]; then
    sed "s#\(0x[0-9a-fA-F]* \).*qemu_sb.bin#\1$app#" "$b/flash_args" > "$OUT/flash_args.tmp"; args="$OUT/flash_args.tmp"
  fi
  (cd "$b" && python -m esptool --chip esp32c3 merge_bin --output "$f" --fill-flash-size 4MB "@$args" >/dev/null)
}

# run_qemu <flash> <efuse> <seconds> <log> : boot normally, serial to <log>, stop after <seconds>
run_qemu() {
  local flash="$1" efuse="$2" secs="$3" log="$4"
  : > "$log"
  qemu-system-riscv32 -M esp32c3 \
    -drive "file=$flash,if=mtd,format=raw" \
    -drive "file=$efuse,if=none,format=raw,id=efuse" \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -global driver=timer.esp32c3.timg,property=wdt_disable,value=true \
    -nic user,model=open_eth -display none -monitor none -serial "file:$log" &
  local pid=$!
  sleep "$secs"; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
}

# efuse <efuse file> <espefuse args...> : QEMU in download mode, espefuse over a local socket
efuse() {
  local efuse_file="$1"; shift
  qemu-system-riscv32 -M esp32c3 \
    -drive "file=$efuse_file,if=none,format=raw,id=efuse" \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -global driver=timer.esp32c3.timg,property=wdt_disable,value=true \
    -global driver=esp32c3.gpio,property=strap_mode,value=0x02 \
    -display none -monitor none -serial "tcp::$QSB_PORT,server,nowait" &
  local pid=$!; sleep 1
  espefuse.py --chip esp32c3 -p "socket://localhost:$QSB_PORT" --before no_reset "$@" || true
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
}

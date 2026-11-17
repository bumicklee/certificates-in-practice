#!/usr/bin/env bash
# 5. eFuse summary of the QEMU eFuse file (default: out/efuse-sb.bin). FILTER='regex' to show only some lines.
. "$(dirname "$0")/lib.sh"
f="${1:-$OUT/efuse-sb.bin}"
if [ -n "${FILTER:-}" ]; then efuse "$f" summary 2>&1 | grep -E "$FILTER"; else efuse "$f" summary; fi

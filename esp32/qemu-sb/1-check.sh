#!/usr/bin/env bash
# 1. Is the ESP32-C3 QEMU there? Which ESP-IDF?
. "$(dirname "$0")/lib.sh"
qemu-system-riscv32 --version | head -1
idf.py --version

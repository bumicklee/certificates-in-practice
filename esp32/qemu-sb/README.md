# qemu-sb: Secure Boot v2 and flash encryption in QEMU (course demo lesson 8-5)

**QEMU only.** Everything here runs on the Mac in Espressif's QEMU (`qemu-system-riscv32 -M esp32c3`). The eFuses
are a 1 KB file (`out/efuse-*.bin`) that you can delete. Nothing opens a serial port: `espefuse.py` only talks
to QEMU over `socket://localhost:5555`. **Never flash these images to a real board, and never run these eFuse
steps against a real port.** On a real chip the same steps cannot be undone.

QEMU emulates the **ESP32-C3**, not the course board ESP32-C5. The C3 only supports **RSA-3072** for Secure Boot v2
(`SOC_SECURE_BOOT_V2_RSA`, no ECDSA), so the practice keys are RSA-3072. The C5 board lab (`../cert-lab`) signs
with ECDSA P-256. The boot chain and the log lines are the same idea on both chips.

```
app/                 hello_world-based app: prints "secure boot: ON/off" and "flash encryption: <mode>"
  sdkconfig.defaults   common (esp32c3, 4 MB flash, partition table at 0xC000 because a signed bootloader is 44 KB)
  sdkconfig.sb         Secure Boot v2, RSA-3072, key ../keys/sb_key.pem, bootloader included in the flash image
  sdkconfig.sb-other   same, signed with ../keys/other_key.pem (step 6)
  sdkconfig.fe         flash encryption, Development mode (step 7, Secure Boot off)
lib.sh               build / make_flash / run_qemu (serial -> log file, killed after N s) / efuse (QEMU download mode + espefuse)
1-check.sh … 8-reset.sh   one script per demo step
keys/  out/          git-ignored: practice keys (chmod 600) and build output, flash and eFuse files, logs
```

## Setup (once)

```bash
brew install libgcrypt glib pixman sdl2 libslirp      # libslirp is the one people usually miss
export PATH=$HOME/.espressif/python_env/idf5.5_py3.14_env/bin:$PATH
export IDF_PYTHON_ENV_PATH=$HOME/.espressif/python_env/idf5.5_py3.14_env
python ~/esp/esp-idf-v5.5/tools/idf_tools.py install qemu-riscv32
```
The scripts load the ESP-IDF v5.5 environment themselves if `idf.py` is not on PATH.

## Steps

| script | what you see |
|---|---|
| `./1-check.sh` | `QEMU emulator version 9.0.0 (esp_develop_9.0.0_20240606)`, `ESP-IDF v5.5` |
| `./2-keys.sh` | two RSA-3072 practice keys (contents never printed) and their **public** key digests |
| `./3-sb-build.sh` | Secure Boot lines from sdkconfig, `Signed … bytes`, `Generated signed binary image` for app and bootloader |
| `./4-sb-run.sh` | first boot on a blank eFuse file: app signature verified, `Burning public key hash to eFuse`, `Writing EFUSE_BLK_KEY0 with purpose 9`, `Secure boot permanently enabled`, app starts. Run again: ROM prints `secure boot verification succeeded` |
| `./5-efuse-summary.sh` | `SECURE_BOOT_EN = True`, `KEY_PURPOSE_0 = SECURE_BOOT_DIGEST0`, `BLOCK_KEY0` = the sb_key digest from step 2. `FILTER='regex'` narrows the output |
| `./6-forged.sh` | app signed with other_key on the same eFuses: `Sig block 0 signed with untrusted key` → `Factory app partition is not bootable` → reset loop, app never starts. `./6-forged.sh bootloader`: the ROM rejects a bootloader signed with other_key and halts |
| `./7-fe-dev.sh` | flash encryption Development mode on its own eFuse file: key generated into KEY0 (purpose 4), flash encrypted, `Flash encryption mode is DEVELOPMENT (not secure)`, key reads as `??`, the app's text is no longer found in the flash file |
| `./8-reset.sh` | deletes the eFuse files; `./4-sb-run.sh` then shows the same first-boot lines again |

`SECS=<n>` changes how long QEMU runs (defaults 8–20 s). Serial logs are in `out/logs/`.

## Two deliberate demo-only settings

* `CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y` in `sdkconfig.sb`. The default is **Secure Download Mode**, and with it
  step 5 fails with `Secure Download Mode is enabled. The tool can not read eFuses.` That is the right state for a
  product; the demo keeps download mode open only so the eFuse file can be read (the boot log then warns
  `UART ROM Download mode kept enabled - SECURITY COMPROMISED`).
* Flash encryption is in **Development** mode (re-flashing plaintext still possible: `1 plaintext flashes left`).
  Release mode is explanation only.

## Clean up

`rm -rf out` removes builds (about 220 MB), flash and eFuse files and logs. `keys/` holds only practice keys. The
course slides show the sb_key digest `37e8bf14…`, so keep `keys/` if the recording should match them (new keys give a
new digest). Rebuild with `./3-sb-build.sh` (the other builds run inside 6 and 7). After the 2026-11-17 measurement
the build folders and flash images were deleted; `out/logs/`, the eFuse file and the digests were kept.

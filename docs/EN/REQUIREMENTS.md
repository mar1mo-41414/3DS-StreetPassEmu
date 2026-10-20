# Required software and hardware

What you need depends on what you want to do. Everything installs in a Python virtual environment
except the system tools marked *(system)*.

## Always

| What | Notes |
|---|---|
| Python 3.10 or newer | 3.12 recommended |
| `pycryptodome >= 3.20` | installed by `pip install -e .` |
| Linux or macOS | Windows is untested |

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"      # pytest and pyctr for the tests; no hardware needed
```

## By task

### Meeting a real console (receive / send boxes)
- A USB Wi-Fi adapter that can ACK a spoofed MAC — [HARDWARE.md](HARDWARE.md). Mandatory.
- A 3DS with custom firmware and **GodMode9**, to dump `aes_keys.txt` (and, only for extracting other
  Miis in bulk — optional, since the Mii Maker's "Send Miis" QR code covers any single Mii — a NAND backup + `boot9.bin` + `otp.bin`) from a console you own.
- `wifit3` (GPLv2, cloned separately into `tools/wifit3`) and **uv** — [SETUP.md](SETUP.md) §3.
- Linux: `libusb` access for your user (the udev rule in `docs/99-wifit3.rules`), or `sudo`.

### Editing or building a box
- Nothing beyond the always-needed packages for `mii_plaza_editor.py` and for building a box from a
  96-byte Mii file.
- **Pillow** (`pip install -e ".[images]"`) to turn PNG/JPEG files into icons (`--large-icon`,
  `--small-icon`, `--header-icon`).
- A **Mii from a QR code image** (`build_tmp_box.py --mii-qr`) needs a QR decoder that returns raw
  bytes: either the `zbarimg` command *(system: `zbar-tools` on Debian/Ubuntu, `brew install zbar` on
  macOS)* or `pyzbar` (`pip install -e ".[mii-qr]"`, which also needs the zbar library *(system)*).
- `qrcode[pil]` (`pip install -e ".[tools]"`) only to *generate* Mii QR images (tests, experiments).

### Checking a box in the emulator ([EMULATOR_TEST.md](EMULATOR_TEST.md))
- **AzaharPlus** (the fork that starts encrypted titles directly).
- Your own **Mii Plaza dump**: the base title's `.app` and the SD update title (e.g. via GodMode9).
- `Xvfb` *(system)*, ImageMagick `import` *(system)*; `gdb-multiarch` *(system)* only for `--trace`.
- Optional helpers for preparing the dump: `pyctr` (in the dev extras), `mtools` *(system)* to copy
  files out of a decrypted CTRNAND image.

### Console-side homebrew (`homebrew/`)
- devkitARM + libctru. Using the official `devkitpro/devkitarm` Docker image avoids installing
  devkitPro on the host.

### Analysis ([ANALYSIS_ENV.md](ANALYSIS_ENV.md))
- Ghidra (headless scripts are Java), `gdb-multiarch`, AzaharPlus.

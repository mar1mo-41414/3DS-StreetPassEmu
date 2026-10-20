# 3DS-StreetPassEmu

**English** | [日本語](README.ja.md)

**A research tool that connects your PC to your own Nintendo 3DS as a virtual StreetPass partner.**
It is neither a 3DS emulator nor an online StreetPass relay. It talks StreetPass directly to
your real console, within radio range, through a USB Wi-Fi adapter.

> **Read this first**
> - You need more than "monitor-mode support": the USB Wi-Fi adapter must be able to
>   **hardware-ACK frames addressed to a spoofed MAC address**. Adapters that cannot will not
>   work. If you are buying a new one, **check wifit3's code before you buy** →
>   [docs/EN/HARDWARE.md](docs/EN/HARDWARE.md)
> - You need your own 3DS with custom firmware (CFW), because the AES key is extracted with
>   GodMode9.
> - **No NAND backup is needed to send a Mii.** The Mii Maker's "Send Miis" function creates a QR
>   code for any Mii on the console; feed a picture of it to `--mii-qr`. A NAND backup is only an
>   optional alternative for extracting Miis in bulk. See the table below for what each feature
>   requires.

## What it can do

- Hold a StreetPass conversation with a real 3DS (in sleep mode) and exchange StreetPass
  messages (TMP Boxes) in both directions
- Display received messages and verify their integrity (HMAC / CRC16 / CCM tag)
- Rewrite outgoing messages: greeting comment, notification text, and the sender Mii (face,
  nickname and identity IDs — the whole thing). The real console's Mii Plaza shows the result
  as "first meeting" or "n-th meeting"
- Get a sender Mii from a Mii QR code image (made with the Mii Maker's "Send Miis"), or — optionally —
  extract the Miis stored on the console in bulk from a NAND backup
- Do all of the above from a **GUI** with tabs (send/receive, Mii, box, identity, files, log) that
  runs in your browser on Windows, macOS and Linux — [docs/EN/GUI.md](docs/EN/GUI.md)
- Build a message from scratch (no genuine box as a template), and check whether Mii Plaza accepts
  a message by running it through the game in an emulator — no console needed (real-console
  confirmation of from-scratch boxes is still pending)
- Documented message formats for a non-Mii-Plaza game (Animal Crossing: New Leaf; static
  analysis only — not yet verified or sent to a real console)

For the full list of what works, what does not yet, open problems, and how to reproduce each
item, see **[docs/EN/STATUS.md](docs/EN/STATUS.md)**.

## What each feature requires

| What you want to do | What you need |
|---|---|
| Meet a real 3DS and receive/save its messages | A CFW 3DS (`aes_keys.txt` dumped with GodMode9) and a spoofed-MAC-capable USB Wi-Fi adapter. **No NAND backup needed** |
| Take a received box as a template and rewrite the comment / notification text / use a different Mii | Same as above |
| Build a box from scratch, or check whether Mii Plaza would accept a box (in an emulator, no console) | Python only for building; an emulator test also needs your own Mii Plaza dump → [docs/EN/EMULATOR_TEST.md](docs/EN/EMULATOR_TEST.md) |
| Send any Mii on the console (yours or others') as the sender | A picture of its **Mii QR code** (Mii Maker → "Send Miis") and a QR decoder (`zbarimg` or `pyzbar`, see [REQUIREMENTS](docs/EN/REQUIREMENTS.md)). **No NAND backup needed** |
| (Optional) Extract Miis from the console in bulk, without making a QR code for each | The above **plus a NAND backup** (and `boot9.bin`, `otp.bin`) |

Supported environment: Linux (including Raspberry Pi) or macOS, Python 3.10+. Windows is untested.

## Quick start

```bash
git clone https://github.com/mar1mo-41414/3DS-StreetPassEmu.git
cd 3DS-StreetPassEmu
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest                      # the test suite needs no hardware
python scripts/gui.py       # optional: the GUI (any OS, opens in your browser)
```

The full walk-through — preparing the Wi-Fi driver, extracting keys, receiving your first
message, then rewriting and sending — is in **[docs/EN/SETUP.md](docs/EN/SETUP.md)**.

## Documentation

| File | Contents |
|---|---|
| [docs/EN/STATUS.md](docs/EN/STATUS.md) | What works (with reproduction steps) / what does not yet / open problems |
| [docs/EN/GUI.md](docs/EN/GUI.md) | The browser-based GUI (`scripts/gui.py`): tabs, workspace, what the send/receive tab needs |
| [docs/EN/REQUIREMENTS.md](docs/EN/REQUIREMENTS.md) | Required software and hardware, per task (Python packages, system tools, emulator, ...) |
| [docs/EN/HARDWARE.md](docs/EN/HARDWARE.md) | Choosing a USB Wi-Fi adapter (how to check spoofed-MAC support), verified-hardware table |
| [docs/EN/SETUP.md](docs/EN/SETUP.md) | From `git clone` to meeting a real console |
| [docs/EN/TROUBLESHOOTING.md](docs/EN/TROUBLESHOOTING.md) | Symptom-based diagnosis |
| [docs/EN/CUSTOM.md](docs/EN/CUSTOM.md) | Customizing outgoing data (`mii_plaza_editor.py`) and building a box from scratch (`build_tmp_box.py`) |
| [docs/EN/EMULATOR_TEST.md](docs/EN/EMULATOR_TEST.md) | Checking a box with Mii Plaza in an emulator, without a console |
| [docs/EN/PROTOCOL_REFERENCE.md](docs/EN/PROTOCOL_REFERENCE.md) | Confirmed protocol and data-format specification |
| [docs/EN/GAME_FORMATS.md](docs/EN/GAME_FORMATS.md) | How Mii Plaza accepts a visitor; Animal Crossing: New Leaf message formats |
| [docs/EN/MONITOR_MODE.md](docs/EN/MONITOR_MODE.md) | Wi-Fi layer (monitor mode) design |
| [docs/EN/ANALYSIS_ENV.md](docs/EN/ANALYSIS_ENV.md) | Dynamic/static analysis environment notes (advanced) |

Japanese versions are in [docs/JA/](docs/JA/).

## Tools

| Script | Purpose |
|---|---|
| `scripts/live_streetpass_test.py` | One-shot connection test against a real console |
| `scripts/streetpass_loop.py` | Repeatedly attempt StreetPass exchanges (outgoing data configurable) |
| `scripts/mii_plaza_editor.py` | Show / verify / rewrite a TMP Box |
| `scripts/decrypt_ctrnand.py` | Decrypt CTRNAND out of a raw NAND backup |
| `scripts/extract_extdata_file.py` | Unpack an extdata file from the NAND |
| `scripts/extract_console_miis.py` | List and extract Miis from the shared Mii database |
| `scripts/extract_recently_played.py` | Scan a dump for "recently played software" lists |

## Please do not paste these into Issues

The following are **personal / console-specific data**. Please **do not paste them** into
Issues, discussions, screenshots or logs (edit them out if you did by mistake):

- NAND backups, `boot9.bin`, `otp.bin`, `movable.sed`, `SecureInfo_A`, `LocalFriendCodeSeed_B`, etc.
- The contents of `aes_keys.txt`, or the `STREETPASS_KEYSLOT_2E_FILE` JSON (KeyX/KeyY)
- Friend codes
- Received TMP Boxes (they contain other people's Miis, comments and IDs), Mii data / QR codes
- Captures or logs that reveal a console's MAC address or console ID

When asking for help, error messages, the output of `mii_plaza_editor.py verify` (item names
and OK/NG), and your adapter model and USB ID are enough — nothing sensitive is needed.
The tests and samples in this repository use **synthetic data**, not raw data from real
consoles. If you add test data in a PR, please use synthetic data as well.

## License

[MIT License](LICENSE). Feel free to clone, modify and redistribute.

## Notes

- This is a research project intended for consoles and software dumps that you own. The
  repository contains no Nintendo executable code, no console-specific keys and no personal
  data; you extract the required key material from your own console yourself
  ([docs/EN/SETUP.md](docs/EN/SETUP.md) §4).
- This is an unofficial project and is not affiliated with Nintendo.
- The Wi-Fi driver layer is a separate repository ([derv82/wifit3](https://github.com/derv82/wifit3),
  GPLv2) that you clone into `tools/wifit3` yourself (it is not included here).

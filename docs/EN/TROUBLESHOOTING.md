# Troubleshooting

A symptom-based guide for when a StreetPass exchange with a real console doesn't work. It is
based on problems actually hit while developing this project.

## First checks (quick diagnosis)

| # | What to check |
|---|---|
| 0 | Is the USB Wi-Fi adapter **spoofed-MAC capable** (`SPOOFABLE` in wifit3)? ([HARDWARE.md](HARDWARE.md)) |
| 1 | Is the 3DS in **sleep mode** (e.g. lid closed, waiting for StreetPass)? Is Wi-Fi on, and is StreetPass enabled for StreetPass Mii Plaza? |
| 2 | Does `STREETPASS_KEYSLOT_2E_FILE` **actually reach the Python process**? (It is not inherited through `sudo` — see A-2 below) |
| 3 | Do `outer HMAC` / `Mii CRC16` / `Mii CCM tag` all show **`OK`** in `mii_plaza_editor.py verify` for the box you are sending? |
| 4 | Is `--cycle-seconds` long enough? (With poor reception, establishing the connection can take 1–2 minutes — B-3 below) |
| 5 | Did you try changing the distance / orientation / adapter position, and the channel (`--channel`)? |

## A. Environment and driver

### A-1. The adapter isn't recognized / the conversation doesn't get established

| Symptom | Cause and fix |
|---|---|
| `wlan_ifaces()` returns an empty list | Unsupported chip, or (on Linux) insufficient permission on the USB device node. Check the `VID:PID` with `lsusb` and compare with wifit3's table. To use it without sudo permanently, apply the udev rule in "Running without sudo on Linux" in [SETUP.md](SETUP.md) |
| `BringUpPermissionsError: ... Resource busy` | Another process is still holding the USB device (e.g. the previous test hasn't fully exited). Find it with `ps aux \| grep streetpass` or `fuser -v /dev/bus/usb/.../...` and end it. `streetpass_loop.py` retries automatically |
| You can see the Probe Request exchange, but the conversation never gets further | Very likely the adapter (chip) **cannot hardware-ACK frames addressed to a spoofed MAC**. "Monitor-mode support" alone is not enough; you need a chip whose wifit3 `FAKE_MAC` is `SPOOFABLE`. See [HARDWARE.md](HARDWARE.md) |
| `libusb-package` fails to install on macOS | There is no wheel for Python 3.14. Specify Python 3.12, e.g. `uv run --python 3.12 ...` |

### A-2. Frames from the console arrive but the conversation doesn't advance (most common)

**If the environment variable `STREETPASS_KEYSLOT_2E_FILE` is not set, the program silently does
not respond — with no error.** The console's encrypted frames arrive fine, we neither decrypt nor
answer them, and the console keeps retransmitting until it times out. There is a real case where
this went unnoticed for over an hour.

`sudo` does not inherit environment variables by default, so pass them explicitly:

```bash
sudo -E env STREETPASS_KEYSLOT_2E_FILE=/path/to/streetpass_keyslot_2e.json \
    STREETPASS_FRIEND_CODE_FILE=/path/to/friend_code.json \
    /full/path/to/uv run --with pycryptodome python ../../scripts/streetpass_loop.py ...
```

### A-3. `uv` isn't found under `sudo`

`env: 'uv': No such file or directory`. root's PATH doesn't include `uv`. Use the full path from
`which uv`.

## B. The connection / conversation isn't established

### B-1. The handshake stalls midway (Probe Request/Response exchange)

Usually a radio (RF) problem. Change the distance, orientation and adapter position and try
again. The console's StreetPass may not be fixed to a single channel, so it is worth trying
different `--channel` values (channel 1 worked reliably in the development environment). Whether
there is a strict response-timing constraint is untested (see "Open problems" in
[STATUS.md](STATUS.md)).

### B-2. The peer console keeps re-sending Probe Requests by itself

The console has taken the "prober" role and is waiting for our reply to its Action frame. We must
reply with an Action frame with the same contents (payload `0x0000`). `StreetPassResponder`
already does this, but beware if you write your own responder.

### B-3. It reaches `peer -> established` but the cycle ends before the response box arrives

The connection was established right at the end of `--cycle-seconds`, so there was no time to
receive the response box. Our send has often completed, but to be sure, use a longer
`--cycle-seconds` such as 240.

### B-4. A console that plays many games isn't detected

Such consoles have an extra leading byte in the service list inside the Nintendo Tag, so
`services_length = 1 + 5×N` (for a console with just one service it's exactly a multiple of 5).
A parser that doesn't expect this layout silently ignores that console's broadcast.
`dot11.parse_nintendo_tag()` in this repository handles it.

## C. A sent box isn't accepted, or looks wrong

### C-1. The LED lights up but nobody appears in Mii Plaza (silently discarded)

The console **discards a message that fails validation with no error at all**. Check that all
three of these are `OK` with `mii_plaza_editor.py verify <box>`:

| Item | Typical cause of failure |
|---|---|
| `outer HMAC` | The HMAC trailer wasn't recomputed after rewriting the body (`mii_plaza_editor.py edit` recomputes it automatically at the end) |
| `Mii CRC16` | FFLStoreData was edited by hand without updating the checksum |
| `Mii CCM tag` | The Mii block was treated as **108 bytes**, leaving the old value from the original box in the last 4 bytes of the tag. The Mii block is **112 bytes (the full 16-byte authentication tag)**. Without it, changing even a single bit of the Mii makes the console silently discard everything. This was the hardest cause to find |

### C-2. Re-sending the same box does nothing

If the `messageId` is the same, the console de-duplicates it as already received. Regenerate the
header IDs of a box you re-send with `mii_plaza_editor.py edit --new-ids`.

### C-3. The Mii's identity I chose changes every time

`--fresh-each-cycle` in `streetpass_loop.py` regenerates not only the header IDs but also **the
sender Mii's `mii_id` every cycle**. Don't use it if you want to keep a specific Mii's identity
(the "n-th meeting" recognition).

### C-4. It says "first meeting", but the detail screen says "n-th meeting"

The popup and the counter on the detail screen are likely looking at different counters — "is
this message new?" versus "how many times have I met this Mii?" (untested). If you change the
message ID every time with `--new-ids`, the same Mii may still be shown as a "first meeting".

### C-5. It isn't registered as a different person / can't be loaded as a Mii QR code

- If the identity (author_id / mii_id) matches a Mii the console already knows, it's shown as
  "n-th meeting". To make it a new visitor, regenerate both with `--new-author-id --new-mii-id`
- The first byte of `mii_id` must have its **upper 4 bits fixed to `0x9`**, otherwise Mii Maker's
  QR import rejects it as "This is not a Mii QR code". `--new-mii-id` satisfies this automatically

### C-6. `ValueError: ... 16 characters or fewer` when rewriting the comment

The greeting comment is limited to 16 characters, matching the console's input field. Mixed
full-width/half-width strings are judged by the count `len()` returns.

## D. Extracting from a NAND backup

| Symptom | Cause and fix |
|---|---|
| `decrypt_ctrnand.py` fails | Use a raw NAND backup, `boot9` and `otp` taken from **the same console**. `ModuleNotFoundError: pyctr` is fixed by `pip install -e ".[dev]"` |
| The mounted decrypted image is empty / unexpected | Mount it read-only with `sudo mount -o loop,ro <img> <dir>` and look under `data/<32-hex-digit id0>/`. The id0 differs per console |
| `extract_extdata_file.py` fails with a "wrong magic" style error | This script only handles **extdata** (the `DIFF` container). System save data (sysdata) is a different container format called `DISA`; pyctr can unpack it, but its content is a 3DS-specific internal filesystem for which this repository has no parser ([STATUS.md](STATUS.md)) |
| `extract_console_miis.py list` shows lots of garbled names like `翿` | Unused slots are filled with repeated `0xff 0x7f`, which looks like `U+7FFF` (`翿`) in UTF-16. The script already excludes them, so if you see this you're not on the latest version |
| Can't extract the friend code automatically | Not supported. Check it on the console screen and enter it by hand in `friend_code.json` ([SETUP.md](SETUP.md) §4.4). StreetPass works without it |

## E. Pitfalls when analyzing / debugging

- **File offsets and Ghidra addresses (VA) are shifted by `+0x00100000`.** If you put a position
  found by a raw byte search straight into Ghidra, you'll be reading completely unrelated code.
  Suspect this first, before concluding that "the method didn't work"
- Ghidra's auto-analysis sometimes marks `exit`-like functions as noreturn by mistake, so the code
  that follows is not recognized as functions. Removing noreturn and recreating the functions
  makes it readable
- What actually runs on a real console is the **updated version distributed via SD etc.** (in
  Mii Plaza's case). If you analyze the base version on the NAND to find addresses and set
  breakpoints at them, you corrupt unrelated instructions and the console throws an SD card
  error. Before setting any breakpoint, always check with `x/i` etc. that the instruction on the
  real console is what you expect
- Using Rosalina's GDB stub "force-debug the next application at launch" stops at the entry
  point. From there, **`detach` without `continue` crashes the process** (no harm to the
  console). A connection is basically one-shot; after disconnecting you have to start debugging
  again from Rosalina, and the port number also changes
- A raw 32-bit byte search for IPC command header constants (e.g. `0x00030104`) can be a useful
  lead but also gives false positives. Disassemble each hit with the correct address translation
  to confirm (see also [GAME_FORMATS.md](GAME_FORMATS.md))

See [ANALYSIS_ENV.md](ANALYSIS_ENV.md) for preparing the analysis environment in detail.

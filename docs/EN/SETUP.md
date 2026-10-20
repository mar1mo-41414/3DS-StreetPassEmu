# Setup Guide (from `git clone` to a live test)

The steps from a fresh clone of this repository to being able to run a live test against a
real 3DS. For technical background see [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md).

## 0. What you need (by feature)

### Hardware

- **A USB Wi-Fi adapter with spoofed-MAC support (mandatory; built-in Wi-Fi cannot be used)**:
  "monitor-mode support" alone is not enough. You need a **chip that can hardware-ACK frames
  addressed to an arbitrary MAC address** (`FakeMacSupport.SPOOFABLE` in wifit3). If you are
  buying a new adapter, **check wifit3's code before you buy**. Details in
  [HARDWARE.md](HARDWARE.md)
- **A 3DS with custom firmware (CFW) where GodMode9 runs** — a console you own. It is required
  to extract the AES key with GodMode9

### Is a NAND backup required?

**It depends on the feature.** If you only want to "meet a real console", no NAND backup is
needed — the `aes_keys.txt` you dump with GodMode9 is enough.

| What you want to do | What you need |
|---|---|
| Hold a StreetPass conversation with a real console and receive/save the peer's message (TMP Box) | `aes_keys.txt` (dumped with GodMode9, §4.2). **No NAND backup needed** |
| Take a received box as a template and rewrite the comment / notification text / sender Mii, then send | Same. The template is the box you first receive from the real console (§4.6). That box already contains **your own console's Mii**, so sending it as-is does not need the NAND |
| Send as a completely different person (a new visitor) | Same (`--new-author-id --new-mii-id`, see [CUSTOM.md](CUSTOM.md)) |
| Extract **other Miis** stored on the console (people you met before, ones imported from QR codes) and send them | A **NAND backup** (plus `boot9.bin` and `otp.bin`) (§4.1 and §4.3) |
| Disclose your own friend code (optional) | Check it on the console screen and set it by hand (§4.4). Automatic extraction from the NAND is not supported |

The NAND backup, `boot9.bin` and `otp.bin` are taken from the same console with GodMode9's
backup features (§4.1). Dumping `aes_keys.txt` does not need a NAND backup file, but it does
require that you can run GodMode9 on the console (i.e. CFW).

## 1. The repository

```bash
git clone https://github.com/mar1mo-41414/3DS-StreetPassEmu.git
cd 3DS-StreetPassEmu
```

## 2. Python environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest   # confirm the whole suite (no hardware needed) passes
```

Dependencies: `pycryptodome>=3.20` (required); `pytest>=8.0` and `pyctr>=0.7` (dev extras,
used for tests that read NAND images, etc.). The full list of software and hardware per task
(Pillow, zbar, AzaharPlus, Xvfb, ...) is in [REQUIREMENTS.md](REQUIREMENTS.md).

## 3. Setting up `tools/wifit3`

It is git-ignored (not committed to this repository), so clone it separately:

```bash
mkdir -p tools
git clone https://github.com/derv82/wifit3 tools/wifit3
(cd tools/wifit3 && uv sync)   # or: uv venv && uv pip install -e .
```

To check whether your chip is supported, follow the steps in [HARDWARE.md](HARDWARE.md) and read
the `FAKE_MAC` declaration under `tools/wifit3/src/wifit3/chips/` (only `SPOOFABLE` chips work).
wifit3 is GPLv2, which is why it lives outside this repository (details in
[MONITOR_MODE.md](MONITOR_MODE.md) §5).

With the USB adapter plugged in:

```bash
cd tools/wifit3
uv run python -c "from wifit3.device.manager import wlan_ifaces; print(wlan_ifaces())"
```

Confirm that at least one supported interface is returned (if nothing is returned, you may
need `sudo`, or the chip may be unsupported). Afterwards return to the repository root
(`cd ../..`).

### Running without sudo on Linux (user privileges only)

wifit3 does not use monitor mode (which needs root); it talks to supported chipsets directly
through libusb to emulate 3DS StreetPass. So `sudo` should not really be necessary — it usually
only looks necessary because the USB device node permissions are root-only.

[`docs/99-wifit3.rules`](../99-wifit3.rules) (a udev rule granting the `plugdev` group access to
the VID:PIDs of every chipset wifit3 supports, extracted from `tools/wifit3/src/wifit3/chips/`)
fixes it:

```bash
sudo cp docs/99-wifit3.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
# Check that your user is in the plugdev group; if not:
#   sudo usermod -aG plugdev $USER   (log in again afterwards)
groups
```

After applying it, replug the adapter (or let `udevadm trigger` re-detect it) and confirm you
can run the check command in §3 and `live_streetpass_test.py` / `streetpass_loop.py` without
`sudo`.

On macOS (Apple Silicon; verified with an RTL8821AU-class adapter) no extra libusb user-space
setup is needed, so this procedure is unnecessary — `uv run --python 3.12 --with pycryptodome python ...`
just works (specify Python 3.12 because `libusb-package` has no wheel for Python 3.14).

## 4. Extracting material from your console

Create a git-ignored `secrets/` directory **next to this repository** (beside
`3DS-StreetPassEmu`). Console-specific keys and personal data go here, and you must **never
commit them** (public/shared keys are hard-coded in the source, so only console-specific
information needs to live here).

```bash
mkdir -p ../secrets
chmod 700 ../secrets
```

From here on, run commands from the **repository root** unless noted otherwise (`../secrets/`
is where secret material lives).

| Section | Contents | Who needs it |
|---|---|---|
| §4.2 | The keyslot 0x2E key (from `aes_keys.txt`) | **Everyone (mandatory)** |
| §4.1, §4.3 | Decrypting CTRNAND; extracting other Miis stored on the console | Only if you want to send other Miis (people you met, etc.). Needs a NAND backup |
| §4.4, §4.5 | Friend code; recently played software | Optional |
| §4.6, §4.7 | Getting a template box and building the outgoing data | **Everyone (mandatory)** |

You obtain the material **with GodMode9 ([`d0k3/GodMode9`](https://github.com/d0k3/GodMode9)) on
your own CFW 3DS**: `aes_keys.txt` and, if you need §4.1/§4.3, the `SysNAND (full)` backup,
`boot9.bin` and `otp.bin`. They are all written to `gm9/out/` on the SD card.

### 4.1 Decrypting CTRNAND (only if you have a NAND backup)

`scripts/decrypt_ctrnand.py` decrypts just the CTRNAND partition out of the raw NAND backup,
producing a FAT16 image you can loop-mount as-is:

```bash
python scripts/decrypt_ctrnand.py \
    <serial>_sysnand_00.bin <serial>_boot9_00.bin <serial>_otp_00.bin \
    ../secrets/ctrnand_decrypted.img

mkdir -p ../secrets/ctrnand_mnt
sudo mount -o loop,ro ../secrets/ctrnand_decrypted.img ../secrets/ctrnand_mnt/
ls ../secrets/ctrnand_mnt/data/   # you should see one 32-hex-digit id0 directory
```

(Internally this uses `ctr_partitions` index 0 of `pyctr.type.nand.NAND`. Verified: the image
decrypted from a real GodMode9 dump matches a known-good decrypted image byte for byte.) §4.3
reads from this mount point. Don't forget `sudo umount ../secrets/ctrnand_mnt/` when finished.

### 4.2 The keyslot 0x2E key (`STREETPASS_KEYSLOT_2E_FILE`)

Take the `slot0x2EKeyX` / `slot0x2EKeyY` lines from the `aes_keys.txt` you dumped with GodMode9
(it is written to `gm9/out/` on the console's SD card; searching for "GodMode9 aes_keys.txt"
turns up plenty of public information on how to generate it; see also
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §10) and make a JSON file of this form:

```json
{
  "key_x": "00112233445566778899aabbccddeeff",
  "key_y": "00112233445566778899aabbccddeeff"
}
```

(16 bytes each = 32 hex digits. The above is an example, not real values.)

```bash
export STREETPASS_KEYSLOT_2E_FILE=$(realpath ../secrets)/streetpass_keyslot_2e.json
```

Alternative: with the on-console homebrew (`homebrew/aes_oracle`, TCP port 17491) you can derive
the CCMP key without bringing the raw KeyX/KeyY to the PC at all (`AesOracleClient` in
`src/streetpass_emu/oracle.py`). In that case the JSON file above is not needed.

### 4.3 Extracting candidate sender Miis (your own profile Mii / Miis you met)

`scripts/extract_console_miis.py` lists and extracts every Mii registered on the console from
the shared Mii database inside the CTRNAND you mounted in §4.1 (CFL_DB, common to Mii Maker and
StreetPass Mii Plaza; for its structure see "Structure of CFL_DB.dat" in
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §9). It holds both
**your own profile Mii** and **other people's Miis that you met via StreetPass or imported from
QR codes** (this is separate from the Miis of "friends" managed by the 3DS Friend List — see
[STATUS.md](STATUS.md); the friend list and friend code cannot be extracted automatically, so
read your friend code off the console screen and enter it by hand in §4.4):

```bash
ID0=$(ls ../secrets/ctrnand_mnt/data)
python scripts/extract_extdata_file.py \
    ../secrets/ctrnand_mnt/data/$ID0/extdata/00048000/f000000b/00000000/00000005 \
    ../secrets/cfl_db.dat

python scripts/extract_console_miis.py list ../secrets/cfl_db.dat
# a list such as [0] offset=0x8 name='(your Mii's nickname)' ... appears

python scripts/extract_console_miis.py extract ../secrets/cfl_db.dat 0 ../secrets/my_mii.bin
```

`my_mii.bin` (a 96-byte FFLStoreData) is the file you swap in as the sender Mii in §4.7.

### 4.4 Friend code (`STREETPASS_FRIEND_CODE_FILE`, optional)

Automatic extraction from the NAND backup is unsolved (the raw bytes of neither
`LocalFriendCodeSeed_B` nor the `frd` module's system save data `00020202` revealed the
principal ID). Check the 12-digit friend code once on the console screen (for example under
System Settings → user information) and **transcribe it by hand**:

```json
{"friend_code": "4126-2228-0312"}
```

Everything works without it (in that case the code honestly answers friend checks with `0`,
meaning "not a friend"). A real friend code is personally identifying, so using one from a
separate test console (for example a broken one) is recommended.

### 4.5 Recently played software list (`STREETPASS_RECENTLY_PLAYED_FILE`, optional)

For customizing the outgoing side (see `src/streetpass_emu/recently_played.py`). Leaving it
unset causes no problems.

### 4.6 The base TMP Box (template)

There is currently no feature to build a TMP Box (a StreetPass message) entirely from scratch;
you **must always use a genuine capture from a real console as a template at least once**, so
that everything other than the Mii and comment (header, icon, country-name table, ...) is
filled in correctly.

Following step ① of §6, run `live_streetpass_test.py` without changing anything and receive
**the genuine outgoing data** your own 3DS sends once (it is saved as
`tmp_box_<mac>_<i>.bin`). Store it under `secrets/outbound/` or similar, and you can reuse it as
a template repeatedly. It is real data containing a personal Mii and comment text, so do not
commit it to the repository.

### 4.7 Building the outgoing data

Rewrite the template to produce the box you will send. `--new-ids` regenerates the header IDs
so the console's de-duplication does not discard it:

```bash
mkdir -p ../secrets/outbound

# (a) Without a NAND backup: keep the template as-is (= your own Mii) and change only the comment
python scripts/mii_plaza_editor.py edit \
    ../secrets/outbound/tmp_box_<mac>_0.bin ../secrets/outbound/my_send_box.bin \
    --new-ids --comment "Hello!"

# (b) With a NAND backup: use another Mii extracted in §4.3 as the sender
python scripts/mii_plaza_editor.py edit \
    ../secrets/outbound/tmp_box_<mac>_0.bin ../secrets/outbound/my_send_box.bin \
    --set-mii-file ../secrets/my_mii.bin --new-ids

# Always verify before sending
python scripts/mii_plaza_editor.py verify ../secrets/outbound/my_send_box.bin
# make sure outer HMAC / Mii CRC16 / Mii CCM tag are all OK
```

This `my_send_box.bin` can be passed directly to `--outbound-tmp-box-body-template` in step ②
of §6. See [CUSTOM.md](CUSTOM.md) for what you can change.

## 5. Offline check

```bash
pytest   # unit tests (no hardware or real-console data needed)

# Look inside a TMP Box body file (if you have the file from §4.7)
python scripts/mii_plaza_editor.py show \
    ../secrets/outbound/my_send_box.bin
```

If `outer HMAC valid: True` and `mii checksum ok: True` are printed, the implementation and the
capture are consistent.

## 6. Live test against a real console

```bash
export STREETPASS_KEYSLOT_2E_FILE=/path/to/streetpass_keyslot_2e.json
export STREETPASS_FRIEND_CODE_FILE=/path/to/friend_code.json  # optional

cd tools/wifit3
```

Monitor-mode operation over USB normally needs `sudo` (wifit3 grabs the USB device directly).
Put the 3DS into **sleep mode (waiting for StreetPass)**.

**① First receive once without any customization (getting the template)**:

```bash
sudo -E uv run --with pycryptodome python ../../scripts/live_streetpass_test.py \
    --channel 1 --seconds 60
```

The genuine TMP Box that your own 3DS sends is saved to `completed_tmp_boxes` (the output path
is shown in the run log). Copy it to `secrets/outbound/` and build `my_send_box.bin` following
§4.7.

**② Repeatedly send the customized box**:

```bash
sudo -E uv run --with pycryptodome python ../../scripts/streetpass_loop.py \
    --channel 1 --cycle-seconds 120 \
    --outbound-tmp-box-body-template ../../../secrets/outbound/my_send_box.bin \
    --out-dir received_boxes/
```

(`--fresh-each-cycle` regenerates not only the header IDs but also the sender Mii's `mii_id`
every cycle — **do not use it** if you want to keep the identity of the Mii you chose in §4.7.
Sending the same box to several peers is naturally dropped by the console's de-duplication
(based on `messageId`), which does no harm.)

The details of every item you can change with `mii_plaza_editor.py edit` — sender Mii, comment,
notification text and so on — are in [CUSTOM.md](CUSTOM.md).

### About the channel

StreetPass on the 3DS may not be fixed to one channel, so it is worth trying different
`--channel` values (in this project channel 1 was confirmed to work reliably).

## 7. Troubleshooting

Symptom-based diagnosis is in **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**. Common ones:

- Frames from the console arrive but the conversation does not advance → `STREETPASS_KEYSLOT_2E_FILE`
  is not being passed through `sudo` (TROUBLESHOOTING.md A-2)
- The LED lights up but nobody appears in Mii Plaza → run `mii_plaza_editor.py verify` and check
  that all three items (HMAC / CRC16 / CCM tag) are `OK` (C-1 there)

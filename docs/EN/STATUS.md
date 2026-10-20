# Status: What Works / What Doesn't Yet / Open Problems

A summary of where the project stands, with reproduction steps. For the confirmed protocol
specification see [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md); for setup see
[SETUP.md](SETUP.md); for customizing outgoing data see [CUSTOM.md](CUSTOM.md); for message
formats of games other than Mii Plaza see [GAME_FORMATS.md](GAME_FORMATS.md).

## What this project is

**A research tool that connects your PC to your own 3DS as a virtual StreetPass partner.**
It is neither a 3DS emulator nor an online StreetPass relay. It talks directly to your real
console, within radio range, through a USB Wi-Fi adapter.

## Verified environment

- 3DS: a Japanese-region original Nintendo 3DS, StreetPass Mii Plaza (updated version)
- OS: Linux x86_64, Raspberry Pi 5 (Linux), macOS (Apple Silicon), Windows (x86-64; command line)
- USB Wi-Fi adapter: a chip with spoofed-MAC support is mandatory. For verified models and how
  to check before buying, see [HARDWARE.md](HARDWARE.md)
- `pytest` passes with no hardware
- **Untested**: other console regions, New 3DS models, adapters other than those above, the GUI's Start/Stop on macOS and Windows
- What each feature requires (a NAND backup is never required to send a Mii: the Mii Maker's "Send Miis" QR code does the job; the NAND is an optional way to extract Miis in bulk) is in the
  table in [SETUP.md](SETUP.md) §0

## 1. What works (with reproduction steps)

| # | What works | How to reproduce |
|---|---|---|
| 1 | Hold a StreetPass conversation with a real 3DS (in sleep mode) and exchange TMP Boxes (the StreetPass message bodies, ~32 KB) in both directions | [SETUP.md](SETUP.md) §3 (Wi-Fi driver), §4.2 (key), §6 → `scripts/live_streetpass_test.py` |
| 2 | Save a TMP Box received from the peer, display its contents (comment, sender Mii, IDs) and verify its HMAC / CRC16 / CCM tag | `scripts/mii_plaza_editor.py show <box>` / `verify <box>` |
| 3 | Rewrite an outgoing TMP Box: greeting comment (up to 16 characters), notification text, header IDs, sender Mii (face, nickname and identity IDs wholesale) | [CUSTOM.md](CUSTOM.md) → `scripts/mii_plaza_editor.py edit` |
| 4 | Send the rewritten box to a real console and have Mii Plaza accept it as a StreetPass encounter. A Mii the console already knows shows as "n-th meeting"; an unknown identity (author_id / mii_id) is treated as a brand-new visitor ("first meeting") | [SETUP.md](SETUP.md) §4.7 and §6 → `scripts/streetpass_loop.py --outbound-tmp-box-body-template <box>` |
| 5 | (With a NAND backup) extract material from the NAND backup alone: decrypt CTRNAND, and pull your own Mii / Miis of people you met before out of the shared Mii database (CFL_DB) | [SETUP.md](SETUP.md) §4.1 and §4.3 → `scripts/decrypt_ctrnand.py` / `extract_extdata_file.py` / `extract_console_miis.py` |
| 6 | Derive the Wi-Fi-layer CCMP key on the PC alone, offline (no queries to the console). Assumes you prepare the AES keyslot 0x2E key material from your own console with GodMode9 | [SETUP.md](SETUP.md) §4.2, [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §3 |
| 7 | Alternative homebrew-based routes on the console: use keyslot 0x2E as an oracle (`homebrew/aes_oracle`), or inject a message through CECD's SPR path (`homebrew/spr_inject`) | `homebrew/aes_oracle/README.md`, the Makefile in each directory (devkitARM) |
| 8 | Decode the structure of the StreetPass message body of a game other than Mii Plaza (Animal Crossing: New Leaf) by static analysis (**not yet verified on a real console**) | [GAME_FORMATS.md](GAME_FORMATS.md) |
| 9 | **Generate a TMP Box from scratch** (no genuine box as a template): builds the header, TLVs, body and HMAC, with icon-image / SMDH import (**accepted by Mii Plaza on real consoles from Linux, macOS and Windows hosts**; includes a random new Mii, prefecture, hobby / pet / dream lines) | [CUSTOM.md](CUSTOM.md) → `scripts/build_tmp_box.py` |
| 10 | Run a box through Mii Plaza in an emulator to see whether it is **accepted**, with no console. Also tells which regions of the box acceptance depends on | [EMULATOR_TEST.md](EMULATOR_TEST.md) → `scripts/emu_receiver_test.py` / `emu_bisect_box.py` |
| 11 | Do all of the editing and building from a browser **GUI** (tabs: send/receive, Mii, box, identity, files, log) on any OS; start/stop the send/receive loop from it | [GUI.md](GUI.md) → `python scripts/gui.py` (editing tabs tested; Start/Stop verified on Linux, not yet on macOS or Windows — the command line works on all three) |

### Conditions for outgoing data to be accepted (Mii Plaza)

After rewriting, the console accepts the sender Mii only if all three of these are correct
(check with `mii_plaza_editor.py verify`):

1. The HMAC-SHA256 at the end of the TMP Box (computed over the body)
2. The sender Mii's CRC16 (inside the FFLStoreData)
3. The **AES-CCM authentication tag (the full 16 bytes)** of the sender Mii blob

Without the third, the console silently discards the Mii with no error (the LED lights up but
nothing appears in Mii Plaza). This was the pitfall that took the longest to find; see
"How Mii Plaza accepts a visitor" in [GAME_FORMATS.md](GAME_FORMATS.md).

## 2. What doesn't work yet

- **Sending a message of a game other than Mii Plaza to a real console**: the message format
  of Animal Crossing: New Leaf is known from static analysis, but confirming it against data
  captured from a real console and integrating it into this project's send path (advertising a
  different title ID as a service) are not implemented.
- **Showing the sender's comment on a real console**: boxes built from scratch are accepted by Mii Plaza on real
  consoles and show the residence, the "recently played" line and the profile lines, but in every real-console
  test so far (including a genuine box sent back unchanged) the greeting **comment was never shown**, and the
  visitor's profile screen has no comment field. The emulator shows it. Where and when a real console shows
  it is unresolved. The areas the builder does not fill (console-specific records, statistics) are zero.
- **Extracting your own friend code from the NAND backup automatically**: the Friend List
  save data embeds a 3DS-specific save-data filesystem that is not analyzed. Check it on the
  console screen and set it by hand (it is not required for StreetPass to work).
- **Extracting friends registered in the Friend List**: same as above. (Miis of people you met
  via StreetPass or imported from Mii QR codes *can* be taken from CFL_DB — row 5 above.)
- **Comments longer than 16 characters**: by design, matching the console's input field limit.
- **Third-party verification over the air with two consoles** (bidirectional capture with
  Wireshark etc.).
- **StreetPass relay servers and SpotPass**: out of scope.

## 3. Open problems

Priority is split into "worth tackling next" and "investigate only if it causes harm".

### Worth tackling next

| Problem | Summary |
|---|---|
| Verifying game-specific messages on a real console | Confirm the Animal Crossing: New Leaf message tables (`userData=1`: house + player, `userData=2`: moving villager) against genuine captures. Two 8-byte fields are unidentified, and the breakdown of the player data (0x6B88 bytes) is undecoded |
| Integrating game-specific messages into the send path | Design how to advertise a different title ID as a service and send the body with a recomputed CRC-32C. Whether to use the HMAC write path is unconfirmed |
| Analyzing other StreetPass-enabled games | Mario Kart 7 (ghosts), Fire Emblem Fates, etc. Each game needs about as much analysis work as Mii Plaza |
| Whether timing constraints exist | The handshake sometimes stalls, but it has not been separated whether that is a Wi-Fi environment issue or a response-timing constraint |

### Not investigated unless it causes harm (low priority)

| Problem | Summary |
|---|---|
| The comment-field header and how a real console picks the visitor lines | The leading u32 is a clamped, monotonically increasing counter. `+0x07` / `+0x08` / `+0x09` select the dog-or-cat, dream and hobby lines (partly mapped, see PROTOCOL_REFERENCE). A real console shows only one or two of them per meeting and lists unknown ones as "-" on the profile screen; how it chooses (progressive reveal over repeated meetings?) is unconfirmed, and the greeting comment itself has never appeared on a real console |
| Unexplained parts of `IdentityPacket` | The meaning of the 8 bytes of `timestamp` after the first 4 (year/month/day) is unknown |
| Generation rule for consoleID / MAC address | The rule is unknown. Random values are used instead, with no problems when talking to real consoles |
| Start of the TMP Box body | The leading triple (title ID / version / display name of the title that last set the sender's Mii) is understood, followed by two constants (`1`, `0x80`) at +0x10 whose meaning is unknown; the display name is the first entry of the SMDH title table |
| Statistics area at the end of the TMP Box body | Looks like a snapshot of the source console's local usage statistics (play times / counts); the individual values are undecoded. Unrelated to acceptance |
| Flags of `CecMessageHeader` | Randomizing all of them was confirmed not to affect acceptance or display. Individual meanings are unknown |
| Mismatch between the "first meeting" popup and the "n-th meeting" counter on the detail screen | Hypothesis: separate per-message and per-Mii counters. Unverified |

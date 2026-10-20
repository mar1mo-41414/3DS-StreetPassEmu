# Protocol Reference (confirmed findings)

This is a reference for implementers that collects only what is **currently confirmed** from the
investigation so far. It leaves out the history of the investigation and failed attempts.

What works, what doesn't yet, and open problems are summarized in [STATUS.md](STATUS.md).

## Contents

1. [Layers and corresponding files](#1-layers-and-corresponding-files)
2. [Communication flow](#2-communication-flow)
3. [CCMP encryption and key derivation](#3-ccmp-encryption-and-key-derivation)
4. [802.11 management frames](#4-80211-management-frames)
5. [SPTCP (transport layer)](#5-sptcp-transport-layer)
6. [SPMTP (message layer) packets](#6-spmtp-message-layer-packets)
7. [Structure of a TMP Box (the StreetPass message body)](#7-structure-of-a-tmp-box-the-streetpass-message-body)
8. [HMAC trailer](#8-hmac-trailer)
9. [Mii QR code / FFLStoreData encryption format](#9-mii-qr-code--fflstoredata-encryption-format)
10. [Required secrets and keys](#10-required-secrets-and-keys)

---

## 1. Layers and corresponding files

| Layer | File | Contents |
|---|---|---|
| 802.11 PHY / management frames | `src/streetpass_emu/dot11.py` | Probe Request/Response, Nintendo Vendor IE, management frame header |
| WPA2 CCMP encryption | `src/streetpass_emu/ccmp.py` | Encrypt/decrypt 802.11 Data frames ⇔ plaintext (AES-CCM) |
| CCMP key derivation | `src/streetpass_emu/crypto.py`, `keyscrambler.py`, `keyslot_2e.py`, `oracle.py` | Build the Hash Block → HMAC-SHA1 → AES-CTR |
| SPTCP (transport layer) | `src/streetpass_emu/sptcp.py` | A layer-2 TCP equivalent: 3-way handshake, segmentation |
| SPMTP (message layer) | `src/streetpass_emu/spmtp.py` | Identity / ModuleFilter / FriendCode / MessageBox / TmpBox packets |
| Mii QR / FFLStoreData | `src/streetpass_emu/mii_qr.py` | Encryption format of the sender Mii (§9) |
| State machine | `src/streetpass_emu/session.py` | `StreetPassResponder`; a hardware-independent pure function |
| Hardware interface | `src/streetpass_emu/driver_bridge.py` | Abstracts wifit3's `WlanInterface` |
| Application data | `mii.py`, `smdh.py`, `recently_played.py`, `friend_code.py` | Structures for Mii / SMDH / recently played software, etc. |
| Live-test scripts | `scripts/live_streetpass_test.py`, `scripts/streetpass_loop.py`, `scripts/mii_plaza_editor.py` | See the README |

Communication with the USB Wi-Fi adapter goes through the user-space driver in `tools/wifit3`
(derv82/wifit3, GPLv2, git-ignored, not committed to this repository). It bypasses the OS Wi-Fi
stack entirely and accesses the USB chip's registers/firmware directly, so the usual AP-mode
abstractions that assume 802.11 authentication/association (hostapd etc.) are unnecessary. See
[MONITOR_MODE.md](MONITOR_MODE.md) for details and [HARDWARE.md](HARDWARE.md) for choosing an
adapter.

## 2. Communication flow

All steps confirmed on a real console:

1. Detect the peer's broadcast Probe Request (SSID `Nintendo_3DS_continuous_scan_000`, with the
   Nintendo Vendor IE) → record the peer's consoleID and reply with a unicast Probe Response
2. Receive a unicast Probe Request from the peer (destination = our MAC, empty SSID, no Nintendo
   Tag) → reply with a second Probe Response
3. Right after that, protected 802.11 Data frames (CCMP) start arriving from the peer
4. **The SPTCP 3-way handshake (SYN → SYN+ACK → ACK) is required every time an SPMTP message is
   sent** (not once per session)
5. SPMTP Info phase: a fixed order
   `0x41→0x42→0x43→0x43→0x11→0x12→0x21→0x22→0x23→0x24→0x31→0x32→0x33→0x34→0x81→0x81`
   (client/master alternating, see §6)
6. Message Box SPMTP phase: the actual TMP Box is transferred with SPTCP segmented transfer
   (window size `0x38b8`); both receiving and sending are implemented and confirmed on a real
   console
7. When neither side has anything left to send, the conversation ends with
   `ACK+FIN` → `ACK+FIN` → `ACK`

## 3. CCMP encryption and key derivation

Used for: every 802.11 Data frame from step 3 onward (`ccmp.py`, AES-CCM, MIC = 8 bytes, EXT_IV
flag set).

Key derivation pipeline (`crypto.py`):

1. Build the **Hash Block**: `host_console_id(8B) + client_console_id(8B) + host_mac(6B)
   + client_mac(6B)` = 0x1C bytes. "host" = the side that sent the Probe Response (us),
   "client" = the side that sent the broadcast Probe Request (the peer)
2. `HMAC-SHA1(key=HMAC_KEY_RETAIL_CANDIDATE, hash_block)`
   — key = `b"Fsd33nrQdg0na29l\x00"` (17 bytes; confirmed by static analysis of the CECD binary,
   byte agreement across two real consoles, and MIC verification of real traffic. A world-wide
   fixed value, not console-specific)
3. Use the first 16 bytes of the digest as the AES-CTR counter
4. AES-CTR-encrypt it with the NormalKey of **keyslot 0x2E** ("StreetPass", KeyType 6 of the PS
   module) → the 16-byte output is the CCMP key
   - `normal_key = rol(rol(keyX,2,128) XOR keyY + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87, 128)`
     (`keyscrambler.py`; a public formula identical to pyctr's `keygen_manual`)
   - KeyX/KeyY come from a GodMode9 dump of your own console (see §10)

Matches exactly on three independent test vectors (two real captures plus the homebrew oracle's
test vector).

## 4. 802.11 management frames

- Probe Request/Response: `parse_probe_request` / `parse_probe_response` / `build_probe_response`
  in `dot11.py`
- Nintendo Vendor Specific IE: OUI `00:1f:32`, type `0x01` (`dot11.build_nintendo_tag`)
- Action frame (category `0x7f`, OUI `00:1f:32`): sent by the console when it acts as the
  "prober", after our Probe Response. In every observed case the payload is a fixed `00 00`, and
  replying with an Action frame of the same content is enough (`dot11.parse_action_frame` /
  `build_action_frame`, `handle_frame` in `session.py`)

## 5. SPTCP (transport layer)

Header (`sptcp.py`, 0x18 = 24 bytes):

| Offset | Size | Field | Value / notes |
|---|---|---|---|
| 0x0 | 2 | magic | `0x5959` |
| 0x2 | 2 | total_size | header(0x18) + payload + 0x18 |
| 0x4 | 4 | constant | `AD DE AF BE` (as a byte sequence) |
| 0x8 | 4 | bytes_sent | **cumulative bytes sent over the whole transfer** (not window-relative) |
| 0xC | 4 | bytes_received | **cumulative bytes received over the whole transfer** |
| 0x10 | 1 | shifted_size | `(0x18+0x18)>>2` = always fixed at `0x0c` |
| 0x11 | 1 | flags | FIN(bit0) / SYN(bit1) / RST(bit2) / PSH(bit3) / ACK(bit4) / END(bit5) |
| 0x12 | 2 | max_buffer_size | default `0x38b8` (`b8 38` as stored LE) |
| 0x14 | 4 | padding | all zero |

The plaintext has `MSDU_PREAMBLE = aa aa 03 00 00 00 08 00 + 00 00` (10 bytes, 802.2 LLC/SNAP-like)
in front of the SPTCP header.

## 6. SPMTP (message layer) packets

### Handshake header (0x10 = 16 bytes)

| Offset | Size | Field |
|---|---|---|
| 0x0 | 2 | magic = `0x6363` |
| 0x2 | 2 | padding |
| 0x4 | 4 | packet_type |
| 0x8 | 4 | zero |
| 0xC | 4 | content_size |

PacketType: `IDENTITY_CLIENT=0x41` / `IDENTITY_MASTER=0x42` / `IDENTITY_ACCEPT=0x43` /
`MODULE_FILTER_CLIENT=0x11` / `MODULE_FILTER_MASTER=0x12` /
`FRIEND_CODE_CLIENT=0x21` / `FRIEND_CODE_MASTER=0x22` /
`FRIEND_FLAG_CLIENT=0x23` / `FRIEND_FLAG_MASTER=0x24` /
`MESSAGE_BOX_METADATA_LIST_CLIENT=0x31` / `_MASTER=0x32` /
`MESSAGE_BOX_METADATA_PARSED_CLIENT=0x33` / `_MASTER=0x34` /
`TMP_BOX_METADATA_LIST=0x81` (same value for client/master)

### IdentityPacket (0x41/0x42, SIZE=0x28=40 bytes)

| Offset | Size | Field | Verification status |
|---|---|---|---|
| 0x00 | 8 | transferable_id | Confirmed on a real console. A fixed value persisted in Mii Plaza's save data (not random per session) |
| 0x08 | 8 | unknown_8 | Meaning unknown (open; see STATUS.md) |
| 0x10 | 4 | session_id | Random per session |
| 0x14 | 6 | original_mac | Different from the continuous-scan MAC. Confirmed to exist as a fixed value inside CFL_DB |
| 0x1A | 2 | padding | |
| 0x1C | 12 | timestamp | Only the first 4 bytes confirmed: year (u16 LE) + 2 zero bytes + month (u8) + day (u8) |

### FriendCodePacket (0x21/0x22, 8 bytes)

A 64-bit value. The upper 32 bits are the checksum (`principal_id_checksum` = upper 7 bits of
SHA1(principal_id as 4 bytes LE)[0]); the lower 32 bits are the principal ID.
`spmtp.friend_code_value_from_string()` converts to and from the 12-digit display form (e.g.
`4126-2228-0312`).

### FriendFlagPacket (0x23/0x24, 4 bytes)

A flag for whether the peer is in the friend list.

### MessageBoxMetadataEntry (0x31–0x34, SIZE=0x20=32 bytes)

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | title_id |
| 0x04 | 1 | send_mode |
| 0x05 | 1 | flag |
| 0x06 | 2 | send_state — the value the peer rewrites and returns in 0x33/0x34. Setting `1` has been shown to start the actual TMP Box transfer |
| 0x08 | 4 | send_size |
| 0x0C | 4 | message_count |
| 0x10 | 16 | unused / reserved (zero-filled) |

### TmpBoxMetadataEntry (0x81, SIZE=8 bytes)

`title_id(4B) + size(4B)`. The whole is `count(4B) + entries`. A real console sends a non-empty
list zero-padded to a fixed 24 slots (`TMP_BOX_METADATA_LIST_SLOT_COUNT=24`).

### TmpBoxHeader (start of the whole TMP Box, TMP_BOX_MAGIC=`0x6161`, 0x14 = 20 bytes)

`magic(2B) + padding(2B) + size(4B) + title_id(4B) + group_id(4B) + message_count(4B)`.

## 7. Structure of a TMP Box (the StreetPass message body)

The data that comes right after `TmpBoxHeader`, passed along as the "body" (the unit handled by
`--outbound-tmp-box-body` and `completed_tmp_boxes`), starts with the following
`CecMessageHeader` (fixed 112 bytes).

### CecMessageHeader (112 bytes, magic=`0x6060`)

Worked out from `NarcolepticK/libctru-cecd`'s `cecApi.h` definition checked against real data:

```c
u16 magic;            // 0x00, = 0x6060
u16 padding;          // 0x02
u32 messageSize;      // 0x04, total size (measured 32692)
u32 totalHeaderSize;  // 0x08, total header length (measured 3348)
u32 bodySize;         // 0x0C, body length (measured 29312)
u32 titleId;          // 0x10, e.g. 0x00020800 (Mii Plaza)
u32 titleId2;         // 0x14
u32 batchId;          // 0x18
u32 unknown_1;        // 0x1C
u8  messageId[8];     // 0x20 -- if the same value is re-sent it's treated as "already received" and de-duplicated
u32 messageVersion;   // 0x28
u8  messageId2[8];    // 0x2C
u8  flags;            // 0x34
u8  sendMethod;       // 0x35
u8  unopened;         // 0x36
u8  newFlag;          // 0x37
u64 senderId;         // 0x38
u64 senderId2;        // 0x40
CecTimestamp sent;     // 0x48 (12B)
CecTimestamp received; // 0x54 (12B)
CecTimestamp created;  // 0x60 (12B)
u8  sendCount;         // 0x6C
u8  forwardCount;      // 0x6D
u16 userData;          // 0x6E
```

`CecTimestamp` = `year:u32 + month:u8 + day:u8 + weekDay:u8 + hour:u8 + minute:u8
+ second:u8 + ms:u16` (`<IBBBBBBH`, 12 bytes).

From `0x70` up to `totalHeaderSize` (measured 3348) is a TLV (Tag-Length-Value) sequence:
`[id:u32][size:u32][data: size bytes, padded to a 4-byte boundary]`. Two `id`s are confirmed on
real data:

- `id=0x4`: the greeting message, UTF-16LE (rewriting it and its display on a real console were
  confirmed)
- `id=0x2`, size=3200: the sending title's icon image (RGB565, 40×40, the PICA200 GPU's standard
  8×8 Z-order tiling)

### Body (offset = `totalHeaderSize`, measured 29312 bytes)

| Offset in body | Size | Contents |
|---|---|---|
| 0x0000 (0) | 8B | Title ID (u64 LE). Forms a set with the version at offset 8 and the display name at offset 48 (below) |
| 0x0008 (8) | 2B | The **TitleVersion** (u16 LE, `major<<10|minor<<4|micro`) of that title. Shown to match, bit for bit, the `title_version` in the console's NAND TMD (`title/00040010/.../content/*.tmd`) |
| 0x0010 (16) | 8B | u32 `1` + u32 `0x80` (constants, identical in every sample) |
| 0x0030 (48) | 0x2000B | **The SMDH Title[16] array** (16 languages × 0x200B: short name 0x80 / long name 0x100 / publisher 0x80, UTF-16LE; order: JA, EN, FR, DE, IT, ES, zh-CN, KO, NL, PT, RU, zh-TW, 4 reserved). The short name of the first entry is the display name that goes with the title ID and version above (examples: `"本体設定"` (System Settings, v12.0.1) / `"Miiスタジオ"` (Mii Maker, v2.1.0)) |
| 0x2038 (8248) | 1152B | Small icon, 24×24, RGB565, Z-order tiling |
| 0x24B8 (9400) | 4608B | Large icon, 48×48, same format |
| 0x36B8 (14008) | 4B | u32 `0x100` (constant) |
| 0x36BC (14012) | 24B | Header of Mii Plaza's built-in Mii DB. magic `"CFPB"` (retail; dev is `"CFPN"`), entry count at +0x14 (1 in the real data). Mii Plaza verifies the magic on receipt |
| 0x36D4 (14036) | 112B | **The sender Mii's encrypted block** (entry 0 of the Mii DB, including the 16-byte tag; see §9) |
| 0x375C (14172) | 4B | **Residence code**: +2 = region (prefecture) code (for Japan the JIS number + 1; only Fukuoka = 41 confirmed on a real console), +3 = country code (1 = Japan). **With empty name tables the residence is shown as "_"**. A region code of `1` means "region not set": the region names are replaced by a placeholder character |
| 0x3760 (14176) | 0x40B×16 | **Country name** strings per language (UTF-16LE, 16 languages). The receiver shows the entry for the *viewer's* console language. The u16 at the end of each entry is zeroed on receipt |
| 0x3B60 (15200) | 0x40B×16 | **Region (prefecture) name** strings per language (same format; e.g. `福岡県` / `Fukuoka` / `福冈县` ...) |
| 0x3F60 (16224) | 16B+string | **Greeting comment field** (below) |
| 0x4484 (17540) | 10B | A copy of the Mii's `mii_id` (not checked by the receiver) |
| 0x4250–0x6240 | — | A series of small records specific to the sending console (3–5 bytes each at a 0x44-byte stride, etc.). **Not validated by the receiver and not needed for acceptance** (confirmed by zeroing). Purpose unknown (presumably mini-game data) |
| 0x7176–0x720F | ~157B | A sequence of numbers that looks like counters / achievements. **Unchanged across independent real captures from the same console.** Most likely a snapshot of the source console's local usage statistics. Unrelated to acceptance |

**What acceptance really needs** (experiments with Mii Plaza in an emulator, [EMULATOR_TEST.md](EMULATOR_TEST.md)):
the message header (+TLVs), the first 0x30 bytes of the body, and a **valid sender Mii** (correct
CRC16 and 16-byte CCM tag). Icons, the multilingual titles, country/region names, the comment, the
console-specific areas above and the statistics can all be zero and the box is still accepted
(the visitor just lacks that information on screen).

### Greeting comment field (body offset 16224)

```
+0x00 (4B): u32 counter  -- not the character count. The receiver clamps it to 999,999. On a real
                             console it grew monotonically across days (14 → 23 → 27), so it looks
                             like an encounter counter
+0x04 (2B): u16 (clamped to 3000)
+0x06 – +0x0B: small byte values (+0x06 is checked against a lookup table, +0x07 is clamped to 2,
               +0x08 to 19, +0x09 to 27; possibly enumerations such as expression / balloon, unconfirmed)
+0x07: **dog or cat** (0 = none, 1 = dog, 2 = cat is a guess, max 2)
+0x08: **dream** (0 = none, 1 = "live long", max 19)
+0x09: **hobby** number (0 = none; picks the "my hobby is ..." line. 1 = illustration, 8 = movies, 9 = internet, 10 = games confirmed, max 27)
 (these three lines were seen on a real console on a repeat visit; an emulator first meeting does not show them)
+0x0A: `1` hides the comment and the line after it (observed in an emulator, meaning unknown)
+0x0C – +0x0F: reserved
+0x10–: UTF-16LE string, NUL-terminated (0x0000)
```

Confirmed across several real captures: the u32 at `+0x00` is **not the character count**
(it measured 14 for a 16-character comment and 23 for a 1-character comment — a value unrelated
to the length. Analysis of the receiving code shows it is a clamped, monotonically increasing counter). **The real boundary of the visible string can be determined correctly
by the NUL terminator (UTF-16LE 0x0000).**

Rewriting (`scripts/mii_plaza_editor.py`) can be done without changing the offsets of any
following region, thanks to the NUL-terminator approach. The length limit is **16 characters**,
matching the console's input field (there is over 12 KB of room before the next known structure,
so the comment can grow or shrink up to 16 characters regardless of the original length).

## 8. HMAC trailer

A "hidden" 32-byte region at the end of the TMP Box body: it doesn't appear in the breakdown of
`bodySize` but is included in the `messageSize` total:

- Position: `whole body[totalHeaderSize + bodySize : +32]`
- Algorithm: **HMAC-SHA256**
- Key: `b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl"` (a 32-byte ASCII fixed string. **A world-wide fixed
  value specific to the Mii Plaza title, not a console-specific key.** Identified by GDB dynamic
  analysis on AzaharPlus plus reading AzaharPlus's own source
  (`Module::Interface::WriteMessageWithHMAC` in `core/hle/service/cecd/cecd.cpp`), and confirmed
  to match two real captures exactly)
- Covered range: **`body[totalHeaderSize : totalHeaderSize+bodySize]` (the body part only, not
  including the header)**

Reference implementation (no `Crypto.Cipher` needed, standard library only):

```python
import hashlib, hmac
key = b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl"
trailer = hmac.new(key, body[header_size:header_size+body_size], hashlib.sha256).digest()
```

This HMAC passes **whichever bytes in the body you rewrite** (comment and sender Mii block
included) as long as it is recomputed correctly. The header part (including the ID-like fields of
`CecMessageHeader`) is outside the HMAC's range, so you can change it freely.

## 9. Mii QR code / FFLStoreData encryption format

The **112-byte** block at TMP Box body offset 14036 has **exactly the same format as an official
3DS Mii QR code** (confirmed by decoding four real-console Mii QR codes with zbarimg and
comparing the data byte for byte with real TMP Box captures).

The key is a world-wide fixed value (from 3dbrew "Mii Maker" and this
[gist](https://gist.github.com/jaames/96ce8daa11b61b758b6b0227b55f9f78)):

```
key = 59 FC 81 7E 64 46 EA 61 90 34 7B 20 E9 BD CE 52  (AES-128)
```

Decryption procedure:

```
nonce(8B)       = blob[0:8]
ciphertext(88B) = blob[8:96]
plaintext88     = AES-CCM-decrypt(ciphertext, key, nonce + 4 zero bytes)
FFLStoreData(96B) = plaintext88[:12] + nonce + plaintext88[12:]
```

Both the QR code and the block inside the TMP Box are 112 bytes (nonce 8 + ciphertext 88 + CCM
authentication tag 16). **The block inside a TMP Box is not 108 bytes ending at the first 12
bytes of the tag**: the following 4 bytes are the remaining 4 bytes of the tag, making the block
112 bytes in total (on three unmodified real boxes the whole 16-byte tag matched the recomputed
value). Mii Plaza decrypts this block with APT:Unwrap (`0x00470104`, in=0x70 / out=0x60 /
nonceOffset=0xC) and **verifies the entire 16-byte tag**, so if you rewrite only 108 bytes the
tag doesn't match and the Mii is silently discarded.

**The correct way to compute the authentication tag**: if you CCM-encrypt and compute the tag on
the 88-byte plaintext with pycryptodome, the ciphertext (keystream) matches the real console but
the tag alone cannot be reproduced. The cause was found by checking against the implementation in
[`KestronProgramming/MiiJS`](https://github.com/KestronProgramming/MiiJS) (`miiCrypto.js`, derived
from kazuki-4ys's
[MiiInfoEditorCTR](https://github.com/kazuki-4ys/kazuki-4ys.github.io/blob/148dc339974f8b7515bfdc1395ec1fc9becb68ab/web_apps/MiiInfoEditorCTR/encode.js)):
**the plaintext passed to CCM must be the full 96 bytes — the 88 bytes plus 8 trailing zero
bytes of padding — not 88 bytes.**

```
plaintext96 = mii[0:12] + mii[20:96] + 8 bytes of zero padding
ciphertext96, tag16 = AES-CCM-encrypt(plaintext96, key, nonce+4 zero bytes, mac_len=16, msg_len=96)
blob(112B) = nonce(8B) + ciphertext96[:88] + tag16
```

(Because the keystream of each CTR-mode block is computed independently per block, leaving out
the trailing 8 bytes happens to leave the first 88 bytes of ciphertext identical, but the CCM
authentication tag depends on the whole message length (96 vs 88), so it differed.) On all four
real Mii QR codes, decrypting and re-encrypting without modification was confirmed to match the
original byte for byte.

### FFLStoreData structure (96 bytes, per WUT/decaf-emu `miidata.h`)

| offset | Size | Field |
|---|---|---|
| 0x00 | 4B | Version etc. bitfield |
| 0x04 | 8B | `author_id` — the ID of the console that created the Mii |
| 0x0C | 10B | `mii_id` (`avatar_id` 4B + `client_id`/deviceHash 6B). The deviceHash was confirmed to match the console's `original_mac`. **The first 8 bytes are reused as-is as the AES-CCM nonce.** The first 4 bytes are not "flags:4 + timestamp:28": the actual generation rule is that **the upper 4 bits of the first byte are always fixed to `0x9`** (the remaining 28 bits are essentially free) — confirmed from the fact that the first byte of a genuine `mii_id` stored on a real console was `0x9d`, and from the generation code of `kazuki-4ys/MiiInfoEditorCTR` (`0x90 + random(0,16)`). If you have a real console load a QR code whose `mii_id` doesn't satisfy this constraint, it is rejected as "This is not a Mii QR code" (handled by `mii_qr.new_mii_id()`) |
| 0x01 (bit 0) | — | **Allow copying** (edit permission in Mii Maker); header byte 1. Set on the Miis of other people seen in real boxes, clear on the console owner's own Mii |
| 0x30 (bit 0) | — | **Sharing**: clear = may be shared (clear in every Mii seen in a real StreetPass box) |
| 0x1A | 20B | `mii_name` (UTF-16LE, 10 characters) |
| 0x48 | 20B | `creator_name` (UTF-16LE, 10 characters) |
| 0x5E | 2B (BE) | `checksum` = CRC16/XMODEM(`data[0:0x5E]`) |

Implemented in `src/streetpass_emu/mii_qr.py` (`decode_mii_blob` / `encode_mii_blob` /
`new_mii_id` / `MiiIdentity`). The nickname decoding and the CRC16 checksum were confirmed to
match on all four real Mii QR codes.

### Face parts and other bitfields (confirmed on a real console)

The detailed layout of the remaining byte range (0x2E–0x47) apart from the table above
(author_id / mii_id / mii_name / creator_name / checksum). The source is the Kaitai Struct spec
[`gen2_wiiu_3ds_miitomo.ksy`](https://github.com/kazuki-4ys/mii2studio/blob/main/gen2_wiiu_3ds_miitomo.ksy)
from [`kazuki-4ys/mii2studio`](https://github.com/kazuki-4ys/mii2studio) (the Mii format common
to the 3DS / Wii U / Miitomo generations). Most of it was confirmed by verifying through real
console QR codes (changing body shape, hairstyle, hair color, glasses and beard together →
correctly reflected in the real console's Mii Maker). Only the `enable` bit of `mole` differed
from the initial assumption (bit15): analyzing the QR code of a Mii to which a "mole" was added
and saved by hand on a real console showed that the `size` / `horizontal` / `vertical` bits
matched exactly while the bit that actually changed was bit0, which was corrected (the table
below is the corrected one).

| offset | Size | Field |
|---|---|---|
| 0x2E | 1B | `body_height` |
| 0x2F | 1B | `body_weight` |
| 0x30 | 1B | `face_color`:3 (bit7-5) + `face_type`:4 (bit4-1) + `mingle`:1 (bit0) |
| 0x31 | 1B | `face_makeup`:4 (bit7-4) + `face_wrinkles`:4 (bit3-0) |
| 0x32 | 1B | `hair_type` (the whole byte) |
| 0x33 | 1B | `unknown_5`:4 (bit7-4) + `hair_flip`:1 (bit3) + `hair_color`:3 (bit2-0) |
| 0x34 | 4B (LE u32) | `eye`: `type`=bit0-5, `color`=bit6-8, `size`=bit9-11, `stretch`=bit13-15, `rotation`=bit16-20, `horizontal`=bit21-24, `vertical`=bit25-29 |
| 0x38 | 4B (LE u32) | `eyebrow`: `type`=bit0-4, `color`=bit5-7, `size`=bit8-11, `stretch`=bit12-14, `rotation`=bit16-19, `horizontal`=bit21-24, `vertical`=bit25-29 |
| 0x3C | 2B (LE u16) | `nose`: `type`=bit0-4, `size`=bit5-8, `vertical`=bit9-13 |
| 0x3E | 2B (LE u16) | `mouth`: `type`=bit0-5, `color`=bit6-8, `size`=bit9-12, `stretch`=bit13-15 |
| 0x40 | 2B (LE u16) | `mouth2`: `mouth_vertical`=bit0-4, `facial_hair_mustache`=bit5-7 |
| 0x42 | 2B (LE u16) | `beard`: `facial_hair_beard`=bit0-2, `facial_hair_color`=bit3-5, `facial_hair_size`=bit6-9, `facial_hair_vertical`=bit10-14 |
| 0x44 | 2B (LE u16) | `glasses`: `type`=bit0-3, `color`=bit4-6, `size`=bit7-10, `vertical`=bit11-14 |
| 0x46 | 2B (LE u16) | `mole`: `size`=bit1-4, `horizontal`=bit5-9, `vertical`=bit10-14, `enable`=**bit0**. Bit15 appears to be unused / always 0 |

**Note**: the reason a modified block (for example a swapped `mii_id`, or another person's Mii
embedded) is silently ignored by a real console is that only 108 bytes were rewritten, leaving the
original box's value in the last 4 bytes of the tag (discarded by Mii Plaza's tag verification).
You can check `Mii CCM tag` with `mii_plaza_editor.py verify`.

### Structure of CFL_DB.dat (the console's Mii database)

The real content of the console's shared extdata `f000000b`
(`extdata/00048000/f000000b/00000000/00000005`) is the following simple fixed-length table:

```
offset 0x00–0x07: file header (8 bytes, not analyzed in detail)
offset 0x08–:     MiiOfficial (mii.py, 0x5C = 92 bytes) laid out slot after slot
                  with no padding between slots
```

Unused slots are filled with a repeating `0xff 0x7f` pattern (decoded as UTF-16LE this turns into
a run of `U+7FFF` (`翿`), so exclude slots whose `mii_name` contains that character to avoid
mistaking them for valid Miis).

`scripts/extract_console_miis.py` lists the valid Mii entries from this table and can write any
entry out as a 96-byte FFLStoreData (the form usable with `--set-mii-file`). The FFLStoreData
restored with `mii_qr.decode_mii_blob()` from a genuine real TMP Box capture (of someone else's
Mii) and the FFLStoreData extracted from CFL_DB with this tool **match in all 96 bytes
(checksum included)** — which also demonstrated that setting the 2 reserved bytes right after the
92 bytes in CFL_DB to a fixed `0x0000` is fine.

### Reference: community Mii editing tools

- [`KestronProgramming/MiiJS`](https://github.com/KestronProgramming/MiiJS) (the JS library behind
  `infinimii.com`) — reads/writes, converts and generates QR codes for the Mii formats of nearly
  every generation: Wii / DS / 3DS / Wii U / Switch / Miitomo. Its `miiCrypto.js` is the
  reference implementation of this section's AES-CCM encryption/decryption
- [`kazuki-4ys/MiiInfoEditorCTR`](https://kazuki-4ys.github.io/web_apps/MiiInfoEditorCTR/) — a web
  app that lets you **edit FFLStoreData itself directly from a form** (name, body shape, gender,
  birthday, face parts, ...), not just via QR codes. The primary source of MiiJS's CCM
  implementation

## 10. Required secrets and keys

| Key / information | Value / source | Console-specific? | Where it lives |
|---|---|---|---|
| keyslot 0x2E KeyX/KeyY | Dump with GodMode9 | KeyX is common to all consoles; KeyY comes from NATIVE_FIRM (model-dependent) | `STREETPASS_KEYSLOT_2E_FILE` (secrets) |
| `HMAC_KEY_RETAIL_CANDIDATE` | `Fsd33nrQdg0na29l\0` | No (world-wide) | Hard-coded in `crypto.py` |
| TMP Box HMAC key | `15cqj40dsrtde8m0fs0cr0x2hzafbfkl` | No (common to the Mii Plaza title) | Hard-coded in `mii_plaza_editor.py` |
| Mii QR AES key | `59FC817E6446EA6190347B20E9BDCE52` | No (world-wide) | Hard-coded in `mii_qr.py` |
| Friend code | Console-specific | Yes | `STREETPASS_FRIEND_CODE_FILE` (secrets) |

### How to obtain the keyslot 0x2E KeyX/KeyY (`aes_keys.txt`)

Use GodMode9 ([`d0k3/GodMode9`](https://github.com/d0k3/GodMode9)) to **obtain `aes_keys.txt` from
your own 3DS**. The two lines `slot0x2EKeyX` and `slot0x2EKeyY` in the obtained file are the values
you need (16 bytes each = 32 hex digits).

- `aes_keys.txt` is generally produced by a community GodMode9 script (such as `DumpAESkey.gm9`)
  and is written to `gm9/out/` on the console's SD card. How to get and run it is public
  information — searching for "GodMode9 aes_keys.txt" turns up plenty
- The generated file contains the keys of several slots. This project uses only the two lines
  `slot0x2EKeyX` / `slot0x2EKeyY`
- Put the values outside `3DS-StreetPassEmu` (e.g. in `secrets/`) as a JSON of the form
  `{"key_x": "<32 hex digits>", "key_y": "<32 hex digits>"}`, and point the environment variable
  `STREETPASS_KEYSLOT_2E_FILE` at that path ([SETUP.md](SETUP.md) §4.2). **Never commit it to the
  repository**
- The `boot9.bin`, `otp.bin` and raw NAND backup needed for decrypting the NAND are also obtained
  with GodMode9's backup features ([SETUP.md](SETUP.md) §4.1)

For setup steps and environment variable details see [SETUP.md](SETUP.md).

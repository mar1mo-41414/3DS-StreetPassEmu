# StreetPass Message Formats per Game

The parts of a StreetPass message (TMP Box) that are common to all titles — header, HMAC
trailer and so on — are summarized in [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md). This file
covers **how the contents of the body differ per title**. Public sources such as 3dbrew do not
document the body formats; you have to take each title's executable code yourself and read it
out by static and dynamic analysis.

Everything here was obtained by analyzing dumps of software the author owns. It does not include
the executable code itself or any keys.

## 1. Identifying a message

A StreetPass "service" is identified by a 5-byte ID (see the
[StreetPass](https://www.3dbrew.org/wiki/StreetPass) page on 3dbrew): the first four bytes are
the low 32 bits of the title ID, and the last byte holds flags such as the send method.

| Title | Service ID (first 4 bytes) | Notes |
|---|---|---|
| StreetPass Mii Plaza | `00 02 08 00` | The main title this project targets |
| Animal Crossing: New Leaf | `00 19 8D 00` | As listed on 3dbrew (EUR). The Japanese amiibo+ edition was confirmed to share the same low 32 bits |
| Ridge Racer | `00 03 58 00` | As listed on 3dbrew |
| The Sims 3 | `00 03 65 00` | As listed on 3dbrew |
| Street Fighter | `00 03 05 00` | As listed on 3dbrew |
| Tomodachi Life (EUR) | `00 08 C5 00` | As listed on 3dbrew |

When a title has several message kinds, some titles distinguish them with the `userData` field of
`CecMessageHeader` (offset 0x6E) — Animal Crossing: New Leaf does.

## 2. How StreetPass Mii Plaza accepts a visitor

For a received message, Mii Plaza checks the following in order. **A message that fails any one of
them is skipped silently, with no error** (the LED lights up but nothing appears in the plaza).

1. The message magic is `0x6060`, the total size is at most `0x19000`, and the body size is at
   least `0x45d8`
2. Each field of the body is clamped into range (out-of-range values are just set to 0, not
   rejected)
3. The sender's Mii database starting at body `0x36bc` is imported:
   - The header magic is `"CFPB"` (retail; the development build uses `"CFPN"`)
   - The **0x70-byte** entry starting at body `0x36d4` is decrypted with the system's `APT:Unwrap`
     (command `0x00470104`; input 0x70 / output 0x60 / nonce offset 0xC / nonce length 10).
     **This verifies the whole 16-byte AES-CCM authentication tag**
   - Then CRC16, `mii_id` not all zeros, `mii_id[0] & 0x20 == 0`, and range checks on every
     CharInfo field (the name contains no `%` or `\`, etc.)
4. The sender's `author_id` (8 bytes) is looked up in a 1000-entry table (12 bytes per entry; a
   match when the state value is not 7) and rejected if found (it looks like a blocklist, but the
   table's origin is unconfirmed)
5. If it passes, it is registered as a visitor. For a known visitor it compares against the saved
   Mii (0x60 bytes) and sets a "contents changed" flag, but that is not a rejection condition

So you can rewrite the Mii's face, nickname and `author_id` / `mii_id` freely, and it will be
accepted **as long as the authentication tag from step 3 is recomputed correctly for the rewritten
content**. Conversely, if the Mii block is mistaken for 108 bytes (up to the first 12 bytes of the
tag) when rewriting, the last 4 bytes of the tag keep the value from the original box, and every
modified Mii is silently discarded at step 3 — this was the problem whose cause stayed unknown the
longest in this project.

## 3. Animal Crossing: New Leaf

**Status: static analysis of the executable code only. It has not yet been confirmed against
genuine messages captured from a real console.** Some offsets seem to match the layout of the
save data known in the community, but they have not been cross-checked from memory.

### 3.1 How sending and receiving work

The game uses the CECD service (`cecd:u` / `cecd:s`) through the `nn::cec::CTR::MessageBox` class
(confirmed from RTTI strings) and owns its own message box. The CEC title ID is `0x198d`
(`0x00198d00`), groupId=1.

The SDK's CECD IPC command header values (also documented on 3dbrew):

| Command | Header value |
|---|---|
| ReadMessage | `0x00030104` |
| WriteMessage | `0x00060104` |
| OpenAndRead | `0x00120104` |
| OpenAndWrite | `0x00110104` |
| ReadMessageWithHMAC | `0x00040106` |
| WriteMessageWithHMAC | `0x00070106` |
| Delete | `0x00080102` |
| ReadData | `0x000A00C4` |

Sending goes `Message::NewMessage` → `SetMessageBody` → `SetExHeader` (id=2: icon, id=4: UTF-16LE
string) → `MessageBox::WriteMessage`. Receiving sorts every message in the inbox by `userData`, and
**discards any message whose body size doesn't match the fixed size exactly**.

### 3.2 Message kind 1 (`userData=1`): house + player (body 0x7DC8 bytes)

Probably the house-data exchange of "Happy Home Showcase".

| Body offset | Size | Contents |
|---|---|---|
| 0x0000 | 4 | magic `0x0700009E` |
| 0x0004 | 4 | CRC-32C (Castagnoli, reflected polynomial `0x82F63B78`, init/xorout=`0xFFFFFFFF`) over 0x7DC0 bytes starting at 0x0008 |
| 0x0008 | 8 | u64 (presumably an ID; unidentified) |
| 0x0010 | 0x1228 | House data (copied from the per-player region in the save at `+0x5d900 + i*0x1228`) |
| 0x1238 | 0x6B88 | Player data (the first 0x6B88 bytes copied; the 0xA8 bytes at `+0x5498` are re-encoded when sending) |
| 0x7DC0 | 8 | 8 bytes derived from save `+0x6e29a` (unidentified) |

On receiving, the code verifies the magic and CRC, compares body `+0x67de` / `+0x67f4` (u16) /
`+0x67f6` (18 bytes) / `+0x6808` with the corresponding positions in its own save, and **does not
import a message from the same town**.

### 3.3 Message kind 2 (`userData=2`): moving villager (body 0x2520 bytes, sent only once)

| Body offset | Size | Contents |
|---|---|---|
| 0x0000 | 4 | CRC-32C (over 0x251C bytes starting at 0x0004) |
| 0x0004 | 4 | State = 2 (ready to send) |
| 0x0008 | 0x2518 | One villager's data |

On receiving, it validates the villager ID (at `+0x2C` in the villager data) and so on, then writes
it into the storage area.

### 3.4 Notes for analysis

- **A file offset in the executable (`.code`) and the virtual address (VA) in Ghidra differ by
  `+0x00100000`.** Don't disassemble the result of a raw byte search as-is.
- Ghidra's auto-analysis sometimes marks `exit`-like functions as noreturn by mistake, leaving
  the code after them unrecognized as functions. Remove noreturn and recreate the functions to
  read them.

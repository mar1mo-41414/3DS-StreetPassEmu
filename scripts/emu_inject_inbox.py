#!/usr/bin/env python3
"""Injects a TMP Box into the CEC InBox of an AzaharPlus emulator NAND.

Lets a (synthetic or captured) StreetPass message be fed to the real Mii Plaza code
running in the emulator, to check whether the *receiver side* accepts it, without a
3DS and without the Wi-Fi path. AzaharPlus' CECD is an HLE re-implementation, so only
the Mii Plaza's own validation (body sanitising, Mii import, blocklist, registration)
is the genuine article; CECD's own checks are not.

What it writes (layout from AzaharPlus src/core/hle/service/cecd/cecd.cpp):

    CEC/<programId>/InBox___/_<base64(messageId)>   the message (magic 0x6060)
    CEC/<programId>/InBox___/BoxInfo_____           header + the first 0x70 bytes of each message
    CEC/<programId>/MBoxInfo____                    unread/new flags set

The base64 alphabet is cecd's "A-Za-z0-9+-" without padding.

Usage:
    python scripts/emu_inject_inbox.py BOX.bin [--nand DIR] [--program-id 00020800] [--clear]
"""
from __future__ import annotations

import argparse
import base64
import struct
from pathlib import Path

DEFAULT_NAND = Path.home() / ".local/share/azaharplus-emu/nand"
CEC_REL = "data/00000000000000000000000000000000/sysdata/00010026/00000000/CEC"
HDR_LEN = 0x70
BOXINFO_HDR_LEN = 0x20


def message_from_file(path: Path) -> bytes:
    data = path.read_bytes()
    if struct.unpack_from("<H", data, 0)[0] == 0x6161:  # received TMP Box: strip TmpBoxHeader
        data = data[0x14:]
    if struct.unpack_from("<H", data, 0)[0] != 0x6060:
        raise ValueError(f"{path}: not a TMP Box message")
    return data


def encode_message_id(msg_id: bytes) -> str:
    return base64.b64encode(msg_id).decode().rstrip("=").replace("/", "-")


def build_boxinfo(old: bytes, messages: list[bytes]) -> bytes:
    """Re-uses max_* limits of the existing BoxInfo and fills in the message list."""
    magic, _pad, _fsize, max_box, _box, max_msgs, _num, max_batch, max_msg = struct.unpack_from(
        "<HHIIIIIII", old, 0)
    assert magic == 0x6262, "InBox BoxInfo_____ has a bad magic"
    heads = b"".join(m[:HDR_LEN] for m in messages)
    box_info_size = BOXINFO_HDR_LEN + len(heads)
    box_size = sum(len(m) for m in messages)
    hdr = struct.pack("<HHIIIIIII", magic, 0, box_info_size, max_box, box_size,
                      max_msgs, len(messages), max_batch, max_msg)
    return hdr + heads


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("box", nargs="?", type=Path, help="TMP Box (0x6161-wrapped or bare 0x6060 message)")
    ap.add_argument("--nand", type=Path, default=DEFAULT_NAND, help="emulator NAND directory")
    ap.add_argument("--program-id", default="00020800", help="CEC mailbox (default: Mii Plaza)")
    ap.add_argument("--clear", action="store_true", help="empty the InBox first (otherwise append)")
    args = ap.parse_args()

    cec = args.nand / CEC_REL / args.program_id
    inbox = cec / "InBox___"
    boxinfo = inbox / "BoxInfo_____"
    if not boxinfo.exists():
        raise SystemExit(f"{boxinfo} not found - run Mii Plaza once in the emulator first")

    existing: list[bytes] = []
    for f in sorted(inbox.glob("_*")):
        if args.clear:
            f.unlink()
        else:
            existing.append(f.read_bytes())

    msgs = list(existing)
    if args.box:
        msg = message_from_file(args.box)
        mid = msg[0x20:0x28]
        name = "_" + encode_message_id(mid)
        (inbox / name).write_bytes(msg)
        msgs.append(msg)
        print(f"wrote {inbox / name} ({len(msg)} bytes, message id {mid.hex()})")

    boxinfo.write_bytes(build_boxinfo(boxinfo.read_bytes(), msgs))
    print(f"BoxInfo_____: {len(msgs)} message(s)")

    mbox = cec / "MBoxInfo____"
    b = bytearray(mbox.read_bytes())
    b[0x40] = 1  # flag_unread
    b[0x41] = 1  # flag_new
    mbox.write_bytes(bytes(b))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

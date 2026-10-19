#!/usr/bin/env python3
"""Extracts real Mii data from a 3DS's own Mii database (CFL_DB, the
shared extdata that Mii Maker / StreetPass Mii Plaza / Friend List all
read from -- ) and converts entries into
a 96-byte FFLStoreData file usable with
`mii_plaza_editor.py edit --set-mii-file` to build StreetPass send data.

CFL_DB.dat layout (reverse-engineered 2026-09-23, no public documentation
found beyond "entries are 0x5c bytes"): an 8-byte file header, followed by
a table of `MiiOfficial` records (mii.py, 0x5C=92 bytes each) packed back
to back. Not every 92-byte slot holds a valid Mii (empty/deleted slots are
skipped based on whether the nickname decodes to something sane).

FFLStoreData (96 bytes, what encode_mii_blob()/--set-mii-file expect) is
MiiOfficial's 92 bytes + 2 reserved bytes (zeroed here -- we don't know
what a real 3DS would put there, but it doesn't matter: mii_qr.py
recomputes the CRC16 checksum and AES-CCM tag over our own bytes, and
Mii Plaza only validates internal consistency, not this reserved data's
"true" original value -- project findings) + a CRC16/XMODEM
checksum.

Usage:
    # List every Mii found in a CFL_DB.dat (or a raw CTRNAND-extracted copy)
    python scripts/extract_console_miis.py list cfl_db.dat

    # Write entry 2 out as a 96-byte FFLStoreData file
    python scripts/extract_console_miis.py extract cfl_db.dat 2 mii_out.bin

See docs/EN/SETUP.md / project findings for how to obtain a CFL_DB.dat
from a NAND dump (extdata/00048000/f000000b/00000000/00000005, itself a
DIFF container -- extract_extdata_file.py unwraps that layer first).
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from streetpass_emu import mii  # noqa: E402
from streetpass_emu.mii_qr import crc16_xmodem  # noqa: E402

HEADER_SIZE = 8
ENTRY_STRIDE = mii.OFFICIAL_SIZE  # 0x5C = 92
FFL_STORE_DATA_SIZE = 0x60  # 96: MiiOfficial(92) + 2 reserved + checksum(2)


def _is_plausible_entry(m: "mii.MiiOfficial") -> bool:
    """Real Miis vs. empty/erased 92-byte slots. Empty slots in CFL_DB are
    filled with a `0xff 0x7f` repeating pattern, which happens to decode as
    valid-looking UTF-16LE text (U+7FFF, '翿') and a plausible-looking
    author_id/mii_id -- so this needs more than just "is it printable"."""
    name = m.core.mii_name
    if not name or not name.strip("\x00"):
        return False
    if "翿" in name:  # the empty-slot fill pattern's tell
        return False
    if not all(0x20 <= ord(c) or c == "　" for c in name if c):
        return False
    if m.core.gender not in (0, 1):
        return False
    if m.core.birth_month > 12 or m.core.birth_day > 31:
        return False
    return True


def find_miis(cfl_db: bytes) -> list[tuple[int, "mii.MiiOfficial"]]:
    """Returns [(byte_offset, MiiOfficial), ...] for every slot that looks
    like a real, non-empty Mii entry."""
    found = []
    offset = HEADER_SIZE
    while offset + ENTRY_STRIDE <= len(cfl_db):
        chunk = cfl_db[offset:offset + ENTRY_STRIDE]
        try:
            m = mii.parse_mii_official(chunk)
        except Exception:
            offset += ENTRY_STRIDE
            continue
        if _is_plausible_entry(m):
            found.append((offset, m))
        offset += ENTRY_STRIDE
    return found


def to_ffl_store_data(raw_92_bytes: bytes) -> bytes:
    """MiiOfficial's 92 raw bytes -> a full 96-byte FFLStoreData with a
    freshly computed CRC16/XMODEM checksum (see module docstring for why
    the 2 reserved bytes being zeroed is fine)."""
    if len(raw_92_bytes) != mii.OFFICIAL_SIZE:
        raise ValueError(f"expected {mii.OFFICIAL_SIZE} bytes, got {len(raw_92_bytes)}")
    body = raw_92_bytes + b"\x00\x00"  # + 2 reserved bytes
    crc = crc16_xmodem(body)
    return body + struct.pack(">H", crc)


def cmd_list(args: argparse.Namespace) -> int:
    data = Path(args.cfl_db).read_bytes()
    entries = find_miis(data)
    if not entries:
        print("no Mii entries found", file=sys.stderr)
        return 1
    for i, (offset, m) in enumerate(entries):
        c = m.core
        author_id_hex = c.author_id.to_bytes(8, "little").hex()
        print(f"[{i}] offset={offset:#x} name={c.mii_name!r} creator={m.creator_name!r} "
              f"author_id={author_id_hex} "
              f"mii_id={mii.build_create_id(c.mii_id).hex()} "
              f"gender={'F' if c.gender else 'M'} birth={c.birth_month}/{c.birth_day}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    data = Path(args.cfl_db).read_bytes()
    entries = find_miis(data)
    if not (0 <= args.index < len(entries)):
        print(f"index {args.index} out of range (found {len(entries)} Miis, use 'list' first)",
              file=sys.stderr)
        return 1
    offset, m = entries[args.index]
    raw_92 = data[offset:offset + ENTRY_STRIDE]
    ffl = to_ffl_store_data(raw_92)
    Path(args.output).write_bytes(ffl)
    print(f"extracted [{args.index}] {m.core.mii_name!r} ({len(ffl)} bytes) -> {args.output}")
    print("use with: python scripts/mii_plaza_editor.py edit <template> <output> "
          f"--set-mii-file {args.output} --new-ids")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list every Mii found in a CFL_DB.dat")
    p_list.add_argument("cfl_db", type=Path)

    p_extract = sub.add_parser("extract", help="write one Mii out as a 96-byte FFLStoreData file")
    p_extract.add_argument("cfl_db", type=Path)
    p_extract.add_argument("index", type=int, help="index from the 'list' command's output")
    p_extract.add_argument("output", type=Path)

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(args)
    return cmd_extract(args)


if __name__ == "__main__":
    raise SystemExit(main())

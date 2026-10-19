#!/usr/bin/env python3
"""Decrypts the CTRNAND partition out of a raw NAND backup (GodMode9's
"SysNAND (full)" dump), producing a plain FAT16 image that can be
loop-mounted directly (`sudo mount -o loop,ro ctrnand.img mnt/`).

This is the first step of project findings's "clone -> NAND dump
-> StreetPassing" pipeline: everything else (own Mii via
extract_console_miis.py, keyslot 0x2E via GodMode9's AES dump script) reads
from files inside this decrypted image. See docs/EN/SETUP.md §4 for the full
walkthrough.

Requires, all from the same GodMode9 "essential files" backup
(Tools > NAND Backup / Restore, or the "essential.exefs" backup option --
GodMode9 writes these into 0:/gm9/out/):
    - the raw NAND backup itself (e.g. `<date>_<serial>_sysnand_00.bin`)
    - `<serial>_boot9_00.bin`
    - `<serial>_otp_00.bin`

Usage:
    python scripts/decrypt_ctrnand.py \\
        <serial>_sysnand_00.bin <serial>_boot9_00.bin <serial>_otp_00.bin \\
        ctrnand_decrypted.img
"""
from __future__ import annotations

import sys
from pathlib import Path

from pyctr.crypto.engine import CryptoEngine
from pyctr.type.nand import NAND

CTR_PARTITION_INDEX = 0  # CTRNAND; see module docstring


def decrypt_ctrnand(nand_path: Path, boot9_path: Path, otp_path: Path, output_path: Path) -> None:
    crypto = CryptoEngine(boot9=str(boot9_path))
    nand = NAND(str(nand_path), crypto=crypto, otp_file=str(otp_path))
    try:
        partition = nand.open_ctr_partition(CTR_PARTITION_INDEX)
        with open(output_path, "wb") as out:
            while True:
                chunk = partition.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
    finally:
        nand.close()


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__)
        return 1
    nand_path, boot9_path, otp_path, output_path = (Path(p) for p in sys.argv[1:5])
    decrypt_ctrnand(nand_path, boot9_path, otp_path, output_path)
    print(f"wrote {output_path.stat().st_size} bytes -> {output_path}")
    print(f"mount it with: sudo mount -o loop,ro {output_path} <mountpoint>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

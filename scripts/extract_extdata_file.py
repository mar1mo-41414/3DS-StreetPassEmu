#!/usr/bin/env python3
"""Extracts a single file from a decrypted 3DS CTRNAND's shared/private
extdata (each extdata file is itself an independent DIFF container with an
IVFC hash tree over its content -- project findings). Reusable helper
for project findings (extracting CFL_DB.dat / friend list data).

Usage:
    python scripts/extract_extdata_file.py <path/to/extdata/file> <output.bin>

Example (Mii database, shared extdata f000000b):
    python scripts/extract_extdata_file.py \\
        ctrnand_mnt/data/<id0>/extdata/00048000/f000000b/00000000/00000005 \\
        cfl_db.dat
"""
from __future__ import annotations

import sys
from pathlib import Path

from pyctr.type.save.diff import DIFF
from pyctr.type.save.partdesc.ivfc import IVFCLevel4Reader


def extract_extdata_file(path: Path) -> bytes:
    diff = DIFF(str(path))
    try:
        partition = diff.partitions[0]
        reader = IVFCLevel4Reader(partition.ivfc_hash_tree)
        return reader.read()
    finally:
        diff.close()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    data = extract_extdata_file(Path(sys.argv[1]))
    Path(sys.argv[2]).write_bytes(data)
    print(f"wrote {len(data)} bytes -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

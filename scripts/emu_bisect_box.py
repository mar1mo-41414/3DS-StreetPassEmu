#!/usr/bin/env python3
"""Zeroes body regions of a genuine TMP Box one at a time and asks the emulator whether
Mii Plaza still accepts it (see emu_receiver_test.py). Finds which regions a synthetic box
really has to fill in.

Offsets are body-relative (the body starts after the message header + TLVs).
The HMAC trailer is not recomputed: AzaharPlus' CECD does not check it.

Usage:
    python scripts/emu_bisect_box.py BOX.bin --azahar AppRun --app base.app --baseline DIR \\
        [--only NAME ...] [--zero 0x4250-0x6240 ...] [--outdir DIR]
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path

# name -> (start, end) body-relative; 
REGIONS = {
    "titles":      (0x0030, 0x2030),   # 16-language SMDH title table
    "icons":       (0x2038, 0x36BC),   # small + large icon
    "country_tbl": (0x3760, 0x3B60),
    "region_tbl":  (0x3B60, 0x3F60),
    "comment":     (0x3F70, 0x4482),   # greeting + the 16-string arrays
    "arrays":      (0x4250, 0x6240),   # console-specific records (unexplained)
    "tail":        (0x6240, 0x7280),   # incl. stats at 0x7176+
    "residence":   (0x375C, 0x3760),   # country/region code word
}


def parse_range(s: str) -> tuple[int, int]:
    a, b = s.split("-")
    return int(a, 0), int(b, 0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("box", type=Path)
    ap.add_argument("--azahar", required=True)
    ap.add_argument("--app", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--only", nargs="*", help="region names to test (default: all)")
    ap.add_argument("--zero", action="append", default=[], metavar="A-B",
                    help="extra ad-hoc body range to zero (a variant of its own)")
    ap.add_argument("--combine", action="store_true", help="also test all selected regions zeroed together")
    ap.add_argument("--outdir", type=Path, default=Path("bisect_out"))
    ap.add_argument("--wait", type=float, default=40)
    args = ap.parse_args()

    data = args.box.read_bytes()
    if struct.unpack_from("<H", data, 0)[0] == 0x6161:
        data = data[0x14:]
    hlen = struct.unpack_from("<I", data, 8)[0]
    args.outdir.mkdir(parents=True, exist_ok=True)

    variants: dict[str, list[tuple[int, int]]] = {}
    for name in (args.only or list(REGIONS)):
        variants[name] = [REGIONS[name]]
    for r in args.zero:
        variants[f"zero_{r}"] = [parse_range(r)]
    if args.combine and len(variants) > 1:
        variants["combined"] = [rg for v in list(variants.values()) for rg in v]
    variants = {"control": []} | variants

    here = Path(__file__).parent
    for name, rngs in variants.items():
        m = bytearray(data)
        for a, b in rngs:
            m[hlen + a:hlen + b] = bytes(b - a)
        f = args.outdir / f"{name}.bin"
        f.write_bytes(m)
        shot = args.outdir / f"{name}.png"
        p = subprocess.run([sys.executable, str(here / "emu_receiver_test.py"), str(f),
                            "--azahar", args.azahar, "--app", args.app, "--baseline", args.baseline,
                            "--shot", str(shot), "--wait", str(args.wait), "--trace"],
                           capture_output=True, text=True)
        out = p.stdout
        reg = "registration reached: yes" in out
        panic = "PANIC      : YES" in out
        trace = next((l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("receiver trace")), "?")
        print(f"{name:14s} {'ACCEPT' if reg else 'reject':7s} {'PANIC ' if panic else ''}{trace}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Forensics tool: scan a binary dump for embedded SMDH Title[] tables
(smdh.py), the structure Mii Plaza's "recently played software" StreetPass
list turned out to embed verbatim.

Built for scanning a real console's own local icon cache -- on real
hardware this lives in the CTRNAND FAT partition at
data/<id>/extdata/00048000/f000000b/00000000/00000003 (; confirmed on two real consoles, mount the CTRNAND FAT partition
read-only and copy that file out, e.g. with fuse-3ds/ninfs's mount_nand)
-- but works on any binary blob, including a decrypted TMP Box capture.

This only finds/decodes the *text* (short/long description, publisher);
the icon bitmap data that follows each Title table in both a real SMDH and
Mii Plaza's embedded copy is not examined.

Usage:
    python scripts/extract_recently_played.py path/to/dump.bin [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))

from streetpass_emu import smdh  # noqa: E402

# Real captures so far always repeated the *same* Title text in every one
# of the 16 language slots -- requiring at least
# this many consecutive identical entries before reporting a match filters
# out incidental false positives from high-entropy data that happens to
# decode to a plausible-looking string once.
MIN_CONSECUTIVE_MATCHES = 2


def _looks_like_real_text(text: str) -> bool:
    """Rejects UTF-16 decodes of high-entropy binary data that happen not
    to raise -- a real title's short/long description is short, mundane
    text, not a wall of rare CJK ideographs (project findings found
    exactly this kind of false positive when scanning naively)."""
    if not text or len(text) > 128:
        return False
    return all(ch.isprintable() and (ch.isascii() or ord(ch) < 0x3100) for ch in text)


def find_title_tables(data: bytes):
    """Yields (offset, [smdh.Title, ...]) for each run of
    MIN_CONSECUTIVE_MATCHES+ identical, plausible-looking Title entries
    found back-to-back at TITLE_ENTRY_SIZE-byte strides."""
    stride = smdh.TITLE_ENTRY_SIZE
    offset = 0
    seen_starts = set()
    while offset + stride <= len(data):
        if offset in seen_starts:
            offset += 2
            continue
        try:
            first = smdh.parse_title(data[offset:offset + stride])
        except (ValueError, UnicodeDecodeError):
            offset += 2
            continue
        if not _looks_like_real_text(first.short_description):
            offset += 2
            continue

        run = [first]
        pos = offset + stride
        while pos + stride <= len(data):
            try:
                next_title = smdh.parse_title(data[pos:pos + stride])
            except (ValueError, UnicodeDecodeError):
                break
            if next_title != first:
                break
            run.append(next_title)
            seen_starts.add(pos)
            pos += stride

        if len(run) >= MIN_CONSECUTIVE_MATCHES:
            yield offset, run
            offset = pos
        else:
            offset += 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dump", help="path to the binary file to scan")
    parser.add_argument("--json", action="store_true", help="output as JSON (recently_played.py's config shape)")
    args = parser.parse_args()

    data = Path(args.dump).read_bytes()
    results = list(find_title_tables(data))

    if not results:
        print("no SMDH Title tables found", file=sys.stderr)
        return 1

    if args.json:
        entries = [
            {"short_title": run[0].short_description, "long_title": run[0].long_description, "publisher": run[0].publisher}
            for _, run in results
        ]
        print(json.dumps({"entries": entries}, ensure_ascii=False, indent=2))
    else:
        for offset, run in results:
            t = run[0]
            print(f"offset {offset:#x}: {len(run)} consecutive identical entries")
            print(f"  short:     {t.short_description!r}")
            print(f"  long:      {t.long_description!r}")
            print(f"  publisher: {t.publisher!r}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

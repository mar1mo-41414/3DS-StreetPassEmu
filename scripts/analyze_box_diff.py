#!/usr/bin/env python3
"""Classifies every byte of a StreetPass TMP Box by comparing several genuine boxes.

Given groups of boxes (one group per console), each byte offset is labelled:

  zero      0x00 in every sample
  global    the same non-zero value in every sample of every console
            (a constant of the title itself -> can be embedded in a synthetic box)
  console   constant inside each console but different between consoles
            (console-specific data -> a synthetic box must choose/generate it)
  dynamic   varies between samples of the *same* console
            (changes with time/state: timestamps, IDs, counters, ...)
  title     (only with --split-by-title) constant while the "last-touched title"
            at the start of the body is the same, but differs between titles
            (icons and multilingual title names)

Input boxes may be either the raw message (magic 0x6060, as `mii_plaza_editor.py`
uses) or a received TMP Box with its 0x14-byte TmpBoxHeader (magic 0x6161); the
latter is stripped automatically.

Usage:
    python scripts/analyze_box_diff.py consoleA=boxA1.bin,boxA2.bin consoleB=boxB1.bin
    python scripts/analyze_box_diff.py 'consoleA=dir/*.bin' consoleB=other.bin --ranges
"""
from __future__ import annotations

import argparse
import glob
import struct
import sys
from pathlib import Path

HEADER_FIXED = 0x70


def load_message(path: Path) -> bytes:
    data = path.read_bytes()
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic == 0x6161:  # TmpBoxHeader (0x14) + message
        data = data[0x14:]
    if struct.unpack_from("<H", data, 0)[0] != 0x6060:
        raise ValueError(f"{path}: not a TMP Box message (magic {magic:#06x})")
    return data


def body_title(msg: bytes) -> bytes:
    """The title ID at the start of the body (the 'last-touched title')."""
    header_len = struct.unpack_from("<I", msg, 8)[0]
    return msg[header_len:header_len + 8]


def classify(groups: dict[str, list[bytes]], split_by_title: bool = False) -> list[str]:
    size = {len(m) for ms in groups.values() for m in ms}
    if len(size) != 1:
        raise ValueError(f"samples differ in size: {sorted(size)}")
    n = size.pop()

    # sub[(console, title)] -> samples; without splitting, one sub-group per console
    sub: dict[tuple[str, bytes], list[bytes]] = {}
    for name, ms in groups.items():
        for m in ms:
            sub.setdefault((name, body_title(m) if split_by_title else b""), []).append(m)

    labels: list[str] = []
    for i in range(n):
        per_sub = {k: {m[i] for m in ms} for k, ms in sub.items()}
        if any(len(v) > 1 for v in per_sub.values()):
            labels.append("dynamic")
            continue
        single = {k: next(iter(v)) for k, v in per_sub.items()}
        values = set(single.values())
        if values == {0}:
            labels.append("zero")
        elif len(values) == 1:
            labels.append("global")
        else:
            per_console_vals: dict[str, set[int]] = {}
            for (name, _t), v in single.items():
                per_console_vals.setdefault(name, set()).add(v)
            labels.append("title" if any(len(v) > 1 for v in per_console_vals.values()) else "console")
    return labels


def ranges(labels: list[str], skip: set[str]) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    start = 0
    for i in range(1, len(labels) + 1):
        if i == len(labels) or labels[i] != labels[start]:
            if labels[start] not in skip:
                out.append((start, i, labels[start]))
            start = i
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("groups", nargs="+", help="NAME=file1,file2,... or NAME=glob (one group per console)")
    ap.add_argument("--ranges", action="store_true", help="also print every non-zero range")
    ap.add_argument("--merge-gap", type=int, default=8,
                    help="merge ranges of the same label separated by at most this many bytes (default 8)")
    ap.add_argument("--body-relative", action="store_true",
                    help="print offsets relative to the start of the body (after the header) instead of the message")
    ap.add_argument("--split-by-title", action="store_true",
                    help="treat boxes with a different 'last-touched title' (body +0) as separate sub-groups")
    args = ap.parse_args()

    groups: dict[str, list[bytes]] = {}
    for spec in args.groups:
        name, _, files = spec.partition("=")
        paths: list[str] = []
        for part in files.split(","):
            paths.extend(sorted(glob.glob(part)) or [part])
        groups[name] = [load_message(Path(p)) for p in paths]
        print(f"{name}: {len(groups[name])} samples", file=sys.stderr)

    labels = classify(groups, args.split_by_title)
    total = len(labels)
    counts = {k: labels.count(k) for k in ("zero", "global", "console", "title", "dynamic")}
    print(f"message size {total} bytes")
    for k, v in counts.items():
        print(f"  {k:8s} {v:6d}  ({100 * v / total:5.1f}%)")

    if args.ranges:
        rs = ranges(labels, {"zero"})
        merged: list[list] = []
        for a, b, lab in rs:
            if merged and merged[-1][2] == lab and a - merged[-1][1] <= args.merge_gap:
                merged[-1][1] = b
            else:
                merged.append([a, b, lab])
        header_len = struct.unpack_from("<I", next(iter(groups.values()))[0], 8)[0]
        base = header_len if args.body_relative else 0
        where = f"body offsets (header = {header_len:#x} bytes)" if args.body_relative else "message offsets"
        print(f"\nnon-zero ranges, {where}:")
        for a, b, lab in merged:
            print(f"  {a - base:#07x}-{b - base:#07x} ({b - a:5d} B)  {lab}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

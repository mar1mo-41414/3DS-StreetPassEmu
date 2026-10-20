#!/usr/bin/env python3
"""Builds a Mii Plaza TMP Box from scratch (no genuine box needed).

    python scripts/build_tmp_box.py --mii my_mii.bin --comment "こんにちは" -o box.bin

--mii takes a raw 96-byte FFLStoreData, or a 112-byte encrypted Mii blob / Mii QR payload;
--mii-qr takes a picture of a Mii QR code instead (needs zbarimg or pyzbar).
Optional: --smdh FILE (names + icons from an SMDH), --large-icon / --small-icon / --header-icon (images, scaled to fit), --title NAME
(the "app" name shown with the visitor), --country N --region N, --counter N.
The result can be fed to the emulator test (scripts/emu_receiver_test.py) or sent with
scripts/streetpass_loop.py --outbound-tmp-box-body.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from streetpass_emu import icon  # noqa: E402
from streetpass_emu.mii_qr_image import MiiQrError, mii_from_qr_image  # noqa: E402
from streetpass_emu.smdh import Title, parse_smdh  # noqa: E402
from streetpass_emu.tmp_box_builder import BoxSpec, build_message, mii_from_blob_or_raw  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--mii", type=Path, help="96-byte FFLStoreData, or a 112-byte Mii blob / QR payload")
    g.add_argument("--mii-qr", type=Path, help="image of a Mii QR code (needs zbarimg or pyzbar)")
    ap.add_argument("--comment", default="")
    ap.add_argument("--notice", default=BoxSpec.notice)
    ap.add_argument("--title", help="name of the 'last used app' shown with the visitor")
    ap.add_argument("--smdh", type=Path, help=".smdh file: sets the app names and both icons")
    ap.add_argument("--header-icon", type=Path, help="image, scaled to 40x40")
    ap.add_argument("--small-icon", type=Path, help="image, scaled to 24x24")
    ap.add_argument("--large-icon", type=Path, help="image, scaled to 48x48")
    ap.add_argument("--country", type=int, default=0)
    ap.add_argument("--region", type=int, default=0)
    ap.add_argument("--counter", type=int, default=1)
    ap.add_argument("-o", "--output", required=True, type=Path)
    a = ap.parse_args()

    try:
        mii = mii_from_qr_image(a.mii_qr) if a.mii_qr else mii_from_blob_or_raw(a.mii.read_bytes())
    except MiiQrError as e:
        ap.error(str(e))
    smdh = parse_smdh(a.smdh.read_bytes()) if a.smdh else None
    spec = BoxSpec(
        mii=mii, comment=a.comment, notice=a.notice,
        titles=[Title(a.title, "", "")] if a.title else (smdh.titles if smdh else None),
        header_icon=icon.from_png(a.header_icon, icon.TLV_SIZE) if a.header_icon else None,
        small_icon=icon.from_png(a.small_icon, icon.SMALL_SIZE) if a.small_icon else (smdh.small_icon if smdh else None),
        large_icon=icon.from_png(a.large_icon, icon.LARGE_SIZE) if a.large_icon else (smdh.large_icon if smdh else None),
        country=a.country, region=a.region, visit_counter=a.counter,
    )
    msg = build_message(spec)
    a.output.write_bytes(msg)
    print(f"wrote {a.output} ({len(msg)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

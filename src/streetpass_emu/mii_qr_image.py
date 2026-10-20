"""Mii QR code image -> FFLStoreData.

A 3DS Mii QR code carries 112 raw bytes (nonce 8 + AES-CCM ciphertext 88 + tag 16, see mii_qr.py).
This module reads the bytes out of an image with an external QR decoder and decrypts them, so a
sender Mii for a TMP Box can be made from nothing but the QR image the Mii Maker displays.

Decoder, first one found: ``pyzbar``, ``opencv-python`` (4.8+, ``detectAndDecodeBytes``), or the
``zbarimg`` command line tool (package ``zbar-tools`` on Debian/Ubuntu, ``zbar`` in Homebrew). The payload
is binary, so a decoder that only returns text is not enough.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .mii_qr import QR_CODE_RAW_SIZE, crc16_xmodem, CHECKSUM_OFFSET, decode_mii_blob, verify_mii_blob_tag


class MiiQrError(ValueError):
    pass


def read_qr_bytes(path: Path) -> bytes:
    """The binary payload of the (single) QR code in the image."""
    try:
        from pyzbar import pyzbar
        from PIL import Image
        codes = pyzbar.decode(Image.open(path))
        if codes:
            return bytes(codes[0].data)
    except ImportError:
        pass
    try:  # OpenCV: pip install opencv-python-headless (works on every OS without a system library)
        import cv2
        det = cv2.QRCodeDetector()
        img = cv2.imread(str(path))
        if img is not None and hasattr(det, "detectAndDecodeBytes"):
            data, _pts, _ = det.detectAndDecodeBytes(img)
            if data:
                data = bytes(data)
                try:  # OpenCV hands back binary QR data as UTF-8 of the Latin-1 text; undo that
                    fixed = data.decode("utf-8").encode("latin-1")
                    if len(fixed) == QR_CODE_RAW_SIZE:
                        return fixed
                except (UnicodeError, ValueError):
                    pass
                return data
    except ImportError:
        pass
    exe = shutil.which("zbarimg")
    if not exe:
        raise MiiQrError("no QR decoder found: `pip install pyzbar` or `pip install opencv-python-headless` "
                         "(or install zbar-tools for zbarimg)")
    # -Sbinary: return the bytes untouched; --raw: no "QR-Code:" prefix; -1: stop after one code
    p = subprocess.run([exe, "--quiet", "--raw", "-Sbinary", "-1", str(path)], capture_output=True)
    if p.returncode != 0 or not p.stdout:
        raise MiiQrError(f"no QR code found in {path}")
    return p.stdout


def mii_from_qr_image(path: Path, *, check: bool = True) -> bytes:
    """Reads a Mii QR image and returns the 96-byte FFLStoreData.

    With ``check`` the AES-CCM tag and the Mii's CRC16 are verified (a corrupt or non-Mii QR code
    raises ``MiiQrError``); Mii Plaza silently drops a Mii that fails either check.
    """
    raw = read_qr_bytes(path)
    if len(raw) < QR_CODE_RAW_SIZE:
        raise MiiQrError(f"QR payload is {len(raw)} bytes, a Mii QR code carries {QR_CODE_RAW_SIZE}")
    raw = raw[:QR_CODE_RAW_SIZE]
    mii = decode_mii_blob(raw)
    if check:
        if not verify_mii_blob_tag(raw):
            raise MiiQrError("CCM tag mismatch: not a (valid) Mii QR code")
        if int.from_bytes(mii[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2], "big") != crc16_xmodem(mii[:CHECKSUM_OFFSET]):
            raise MiiQrError("Mii checksum (CRC16) mismatch")
    return mii

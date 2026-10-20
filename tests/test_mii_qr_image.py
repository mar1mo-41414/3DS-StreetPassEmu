import shutil

import pytest

from streetpass_emu import mii_qr
from streetpass_emu.mii_qr_image import MiiQrError, mii_from_qr_image

qrcode = pytest.importorskip("qrcode")
pytest.importorskip("PIL")
_HAS_DECODER = shutil.which("zbarimg") is not None


def render(payload: bytes, path):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=4, box_size=6)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.make_image().save(path)


@pytest.mark.skipif(not _HAS_DECODER, reason="zbarimg not installed")
def test_qr_image_roundtrip(tmp_path):
    mii = bytes(range(96))
    payload = mii_qr.encode_mii_qr_payload(mii)
    img = tmp_path / "mii.png"
    render(payload, img)
    got = mii_from_qr_image(img)
    # the checksum bytes are recomputed on encode; everything else must survive
    assert got[:0x5E] == mii[:0x5E]


@pytest.mark.skipif(not _HAS_DECODER, reason="zbarimg not installed")
def test_corrupt_payload_is_rejected(tmp_path):
    payload = bytearray(mii_qr.encode_mii_qr_payload(bytes(range(96))))
    payload[100] ^= 0xFF
    img = tmp_path / "bad.png"
    render(bytes(payload), img)
    with pytest.raises(MiiQrError):
        mii_from_qr_image(img)
    assert len(mii_from_qr_image(img, check=False)) == 96


def test_image_without_qr(tmp_path):
    from PIL import Image
    img = tmp_path / "blank.png"
    Image.new("RGB", (100, 100), "white").save(img)
    with pytest.raises(MiiQrError):
        mii_from_qr_image(img)


def test_opencv_path(tmp_path, monkeypatch):
    pytest.importorskip("cv2")
    import sys

    monkeypatch.setattr(shutil, "which", lambda _n: None)          # no zbarimg
    monkeypatch.setitem(sys.modules, "pyzbar", None)                # no pyzbar
    mii = bytes(range(96))
    img = tmp_path / "mii.png"
    render(mii_qr.encode_mii_qr_payload(mii), img)
    assert mii_from_qr_image(img)[:0x5E] == mii[:0x5E]

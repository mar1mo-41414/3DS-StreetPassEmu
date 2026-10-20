import shutil

import pytest

from streetpass_emu import mii_qr
from streetpass_emu.mii_qr_image import MiiQrError, mii_from_qr_image

qrcode = pytest.importorskip("qrcode")
pytest.importorskip("PIL")
pytestmark = pytest.mark.skipif(shutil.which("zbarimg") is None, reason="zbarimg not installed")


def render(payload: bytes, path):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=4, box_size=6)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.make_image().save(path)


def test_qr_image_roundtrip(tmp_path):
    mii = bytes(range(96))
    payload = mii_qr.encode_mii_qr_payload(mii)
    img = tmp_path / "mii.png"
    render(payload, img)
    got = mii_from_qr_image(img)
    # the checksum bytes are recomputed on encode; everything else must survive
    assert got[:0x5E] == mii[:0x5E]


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

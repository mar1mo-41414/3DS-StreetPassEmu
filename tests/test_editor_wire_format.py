import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from mii_plaza_editor import TmpBox  # noqa: E402

from streetpass_emu.mii_qr import crc16_xmodem
from streetpass_emu.tmp_box_builder import BoxSpec, build_message


def test_editor_accepts_a_box_saved_from_the_wire():
    mii = bytearray(range(96))
    mii[0x5E:0x60] = crc16_xmodem(bytes(mii[:0x5E])).to_bytes(2, "big")
    msg = build_message(BoxSpec(mii=bytes(mii), comment="こんにちは"))
    wire = b"\x61\x61" + bytes(0x12) + msg      # TmpBoxHeader (0x14 bytes) + message
    box = TmpBox(wire)
    assert box.get_comment() == "こんにちは"
    assert box.verify_hmac() and box.verify_mii_tag()
    box.set_comment("やあ")
    box.recompute_hmac()
    assert bytes(box.data[:2]) == b"\x60\x60" and box.verify_hmac()   # saved bare: what the loop expects

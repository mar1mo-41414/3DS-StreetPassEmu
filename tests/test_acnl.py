import os
import random

import pytest

from streetpass_emu import acnl


def fake_player(name="テスト", town="むら", pid=0x1234, tid=0x4321) -> bytes:
    p = bytearray(random.Random(1).randbytes(acnl.PLAYER_SIZE))
    p[0x55A6:0x55A8] = pid.to_bytes(2, "little")
    p[0x55A8:0x55A8 + 20] = (name.encode("utf-16le") + bytes(20))[:20]
    p[0x55BC:0x55BE] = tid.to_bytes(2, "little")
    p[0x55BE:0x55BE + 18] = (town.encode("utf-16le") + bytes(18))[:18]
    return bytes(p)


def make() -> acnl.AcnlHouseMessage:
    return acnl.AcnlHouseMessage(id64=bytes(range(8)), house=random.Random(2).randbytes(acnl.HOUSE_SIZE),
                                 player=fake_player(), tail=b"\x01" * 8, notice="むら\nテストさんのモデルハウス")


def test_crc32c_known_vector():
    assert acnl.crc32c(b"123456789") == 0xE3069283      # the standard CRC-32C check value


def test_build_parse_roundtrip_and_sizes():
    m = make()
    raw = m.build()
    r = acnl.parse_message(raw)
    assert (r.magic_ok, r.crc_ok, r.hmac_ok, r.user_data) == (True, True, True, 1)
    p = r.message
    assert p.house == m.house and p.player == m.player and p.tail == m.tail and p.id64 == m.id64
    assert (p.player_name, p.town_name, p.player_id, p.town_id) == ("テスト", "むら", 0x1234, 0x4321)
    assert p.notice == m.notice
    hsize = 0x70 + 8 + 3200 + 8 + 2 * len(m.notice)
    hsize += -hsize % 4                                              # header sizes are padded to 4 bytes
    assert int.from_bytes(raw[8:12], "little") == hsize and len(raw) == hsize + acnl.BODY_SIZE + 32 and raw[0x6E] == 1


def test_wrapped_tmp_box_is_accepted():
    raw = make().build()
    assert acnl.parse_message(b"\x61\x61" + bytes(0x12) + raw).crc_ok


def test_tampering_is_detected():
    raw = bytearray(make().build())
    hs = int.from_bytes(raw[8:12], "little")
    raw[hs + 0x100] ^= 1
    r = acnl.parse_message(bytes(raw))
    assert not r.crc_ok and not r.hmac_ok


def test_wrong_title_and_kind_are_rejected():
    raw = bytearray(make().build())
    raw[0x10] ^= 1
    with pytest.raises(ValueError):
        acnl.parse_message(bytes(raw))
    raw = bytearray(make().build())
    raw[0x0C:0x10] = (0x2520).to_bytes(4, "little")
    with pytest.raises(ValueError, match="kind 1"):
        acnl.parse_message(bytes(raw))


def test_from_save_copies_the_right_regions():
    save = bytearray(random.Random(3).randbytes(563968))
    save[0xA0:0xA0 + acnl.PLAYER_SIZE] = fake_player("さくら", "はな")
    msg = acnl.from_save(bytes(save), os.urandom(8))
    assert msg.house == bytes(save[0x5D900:0x5D900 + acnl.HOUSE_SIZE])
    assert msg.tail == bytes(save[0x6E29A:0x6E2A2])
    assert msg.notice == "はな\nさくら" and acnl.parse_message(msg.build()).hmac_ok


def test_retarget_identity_rewrites_every_copy_and_keeps_the_rest():
    player = bytearray(fake_player())
    block = bytes(player[0x55A6:0x55A6 + acnl.IDENTITY_SIZE])
    for off in (0x56, 0x8C6, 0x1136):                     # design patterns store their creator too
        player[off:off + len(block)] = block
    new = acnl.retarget_identity(bytes(player), player_id=0xBEEF, player_name="あいう", town_id=0xCAFE, town_name="たうん")
    msg = acnl.AcnlHouseMessage(id64=bytes(8), house=bytes(acnl.HOUSE_SIZE), player=new)
    assert (msg.player_id, msg.player_name, msg.town_id, msg.town_name) == (0xBEEF, "あいう", 0xCAFE, "たうん")
    assert new.count(block) == 0 and len(new) == len(player)
    diff = [i for i in range(len(new)) if new[i] != player[i]]
    assert all(0x55A6 <= i < 0x55A6 + acnl.IDENTITY_SIZE or any(o <= i < o + len(block) for o in (0x56, 0x8C6, 0x1136))
               for i in diff)
    assert acnl.parse_message(msg.build()).crc_ok and acnl.parse_message(msg.build()).hmac_ok


def test_retarget_identity_validates():
    with pytest.raises(ValueError):
        acnl.retarget_identity(fake_player(), player_id=1, player_name="", town_id=2, town_name="x")
    with pytest.raises(ValueError):
        acnl.retarget_identity(fake_player(), player_id=1, player_name="あ" * 9, town_id=2, town_name="x")
    with pytest.raises(ValueError):
        acnl.retarget_identity(b"short", player_id=1, player_name="a", town_id=2, town_name="x")


def test_wrap_tmp_box_header_matches_the_genuine_one():
    raw = make().build()
    box = acnl.wrap_tmp_box(raw)
    from streetpass_emu import spmtp
    h = spmtp.parse_tmp_box_header(box[:20])
    assert (h.size, h.title_id, h.group_id, h.message_count) == (len(raw) + 20, 0x00198D00, 1, 1)
    assert acnl.parse_message(box).hmac_ok

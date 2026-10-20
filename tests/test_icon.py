import random

import pytest

from streetpass_emu import icon


def test_morton_covers_each_tile_slot_once():
    assert sorted(icon._morton(x, y) for y in range(8) for x in range(8)) == list(range(64))


def test_first_pixels_follow_z_order():
    # within a tile the order is (0,0) (1,0) (0,1) (1,1) (2,0) ...
    assert [icon._morton(x, y) for x, y in [(0, 0), (1, 0), (0, 1), (1, 1), (2, 0), (0, 2), (4, 0), (0, 4)]] \
        == [0, 1, 2, 3, 4, 8, 16, 32]


@pytest.mark.parametrize("size", [icon.SMALL_SIZE, icon.TLV_SIZE, icon.LARGE_SIZE])
def test_bytes_roundtrip_is_lossless(size):
    rnd = random.Random(size)
    raw = bytes(rnd.randrange(256) for _ in range(icon.icon_bytes(size)))
    assert icon.encode(icon.decode(raw, size), size) == raw


def test_pixel_lands_in_the_right_tile():
    size = 16
    px = [(0, 0, 0)] * (size * size)
    px[9 * size + 10] = (255, 0, 0)          # x=10, y=9 -> tile (1,1) = tile 3, inside (2,1)
    raw = icon.encode(px, size)
    idx = 3 * 64 + icon._morton(2, 1)
    assert raw[idx * 2:idx * 2 + 2] == (0xF800).to_bytes(2, "little")
    assert sum(1 for i in range(0, len(raw), 2) if raw[i:i + 2] != b"\0\0") == 1


def test_rejects_bad_sizes():
    with pytest.raises(ValueError):
        icon.encode([(0, 0, 0)] * 25, 5)
    with pytest.raises(ValueError):
        icon.decode(bytes(10), 8)

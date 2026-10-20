"""Residence of the sender as Mii Plaza shows it ("<region> の <name> です").

The box carries a country code and a region code plus the country / region names in 16 languages
(tmp_box_builder). For Japan the region code is the JIS prefecture number + 1 (code 1 means "not
set"). Only Fukuoka (JIS 40 -> 41) has been confirmed against a real console; the other 46 follow the
same rule and are unconfirmed.
"""
from __future__ import annotations

from typing import Optional

COUNTRY_JAPAN = 1

# JIS X 0401 order: index 0 is prefecture number 1
JP_PREFECTURES: list[tuple[str, str]] = [
    ("北海道", "Hokkaido"), ("青森県", "Aomori"), ("岩手県", "Iwate"), ("宮城県", "Miyagi"),
    ("秋田県", "Akita"), ("山形県", "Yamagata"), ("福島県", "Fukushima"), ("茨城県", "Ibaraki"),
    ("栃木県", "Tochigi"), ("群馬県", "Gunma"), ("埼玉県", "Saitama"), ("千葉県", "Chiba"),
    ("東京都", "Tokyo"), ("神奈川県", "Kanagawa"), ("新潟県", "Niigata"), ("富山県", "Toyama"),
    ("石川県", "Ishikawa"), ("福井県", "Fukui"), ("山梨県", "Yamanashi"), ("長野県", "Nagano"),
    ("岐阜県", "Gifu"), ("静岡県", "Shizuoka"), ("愛知県", "Aichi"), ("三重県", "Mie"),
    ("滋賀県", "Shiga"), ("京都府", "Kyoto"), ("大阪府", "Osaka"), ("兵庫県", "Hyogo"),
    ("奈良県", "Nara"), ("和歌山県", "Wakayama"), ("鳥取県", "Tottori"), ("島根県", "Shimane"),
    ("岡山県", "Okayama"), ("広島県", "Hiroshima"), ("山口県", "Yamaguchi"), ("徳島県", "Tokushima"),
    ("香川県", "Kagawa"), ("愛媛県", "Ehime"), ("高知県", "Kochi"), ("福岡県", "Fukuoka"),
    ("佐賀県", "Saga"), ("長崎県", "Nagasaki"), ("熊本県", "Kumamoto"), ("大分県", "Oita"),
    ("宮崎県", "Miyazaki"), ("鹿児島県", "Kagoshima"), ("沖縄県", "Okinawa"),
]


def region_code(jis_number: int) -> int:
    return jis_number + 1


def find_prefecture(query: str) -> Optional[tuple[int, str, str]]:
    """``(region code, Japanese name, English name)`` for a Japanese name (with or without the
    県/府/都 suffix), an English name, or a JIS prefecture number 1-47; ``None`` if unknown."""
    q = query.strip()
    if not q:
        return None
    for i, (ja, en) in enumerate(JP_PREFECTURES, start=1):
        if q in (ja, en) or q.lower() == en.lower() or (len(ja) > 2 and q == ja[:-1]) or q == str(i):
            return region_code(i), ja, en
    return None


def prefecture_of_code(code: int) -> Optional[tuple[str, str]]:
    return JP_PREFECTURES[code - 2] if 2 <= code <= 48 else None

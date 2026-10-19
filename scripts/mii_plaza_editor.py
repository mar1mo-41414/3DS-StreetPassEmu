"""Mii Plaza StreetPass TMP Boxの汎用編集ツール(docs/PROTOCOL_REFERENCE.md参照)。

任意の実機キャプチャ(TMP Box body部分、調査結果の構造)を
入力に取り、あいさつコメント欄の書き換え・重複排除回避用IDのランダム化・
送信者Miiのmii_id再暗号化・HMACトレーラーの再計算を行う。

入力ファイルは「TMP Box body」形式(magic 0x6060から始まる、
CecMessageHeader(112バイト固定 + TLV) + body(29312バイト程度) + HMAC
トレーラー32バイト)。
scripts/live_streetpass_test.py --outbound-tmp-box-body に渡すファイルと
同じ形式で、そのファイルの completed_tmp_boxes 保存結果(tmp_box_*.bin)
がそのまま入力として使える。

【重要な制約・未検証事項は 調査結果 を参照】
- コメント欄先頭のu32フィールドは文字数ではないと実機で確認済み
  (調査結果: 16文字のコメントで14、1文字のコメントで
  23という、文字数と無関係な値が実測された)。本ツールは代わりに
  NUL終端(UTF-16LEの0x0000)を実際の文字列の境界として扱う(実機の
  2つの実キャプチャ双方でこの方式が正しいことを確認済み)
- コメント欄は実機Mii Plazaの入力欄自体の上限に合わせ16文字までで書き換え
  可能(2026-09-23確定。次の既知構造まで12KB以上の余白があるため、元の
  文字数に関わらず16文字まで安全に伸長できる。調査結果)
- mii_id差し替え・ヘッダID全ランダム化を行っても、実機は依然「同じMii」と
  認識し続けることを確認済み。このツールは
  「既知の安全な操作」を提供するだけで、識別回避を保証するものではない

使い方:
    # 内容を表示するだけ(書き換えなし)
    python scripts/mii_plaza_editor.py show tmp_box_body.bin

    # あいさつコメントを書き換え(16文字まで)、再送用に諸ID再生成
    python scripts/mii_plaza_editor.py edit tmp_box_body.bin out.bin \\
        --comment "R8新しいコメントだよ" --new-ids --new-mii-id

    # HMAC/CRC16の検証のみ
    python scripts/mii_plaza_editor.py verify tmp_box_body.bin
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import os
import struct
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))

from streetpass_emu.mii_qr import (  # noqa: E402
    AUTHOR_ID_OFFSET,
    CHECKSUM_OFFSET,
    FFL_STORE_DATA_SIZE,
    MII_ID_OFFSET,
    MiiIdentity,
    TMP_BOX_MII_BLOB_LEN,
    crc16_xmodem,
    decode_mii_blob,
    encode_mii_blob,
    new_mii_id,
    verify_mii_blob_tag,
)
from game_profiles import GameProfile, GAME_PROFILES, DEFAULT_PROFILE, get_profile  # noqa: E402

# CecMessageHeaderの各フィールドオフセット。
# これは3dbrew/NetPassで確認済みの通り全ての
# StreetPass対応タイトルで共通の固定フォーマットなので、ゲーム固有の
# データ(scripts/game_profiles.py)には含めない。
MESSAGE_ID_OFFSET = 0x20
MESSAGE_ID2_OFFSET = 0x2C
BATCH_ID_OFFSET = 0x18
SENDER_ID_OFFSET = 0x38
SENDER_ID2_OFFSET = 0x40
CREATED_OFFSET = 0x60

# 調査結果: まだ個別に触っていなかったフィールド
TITLE_ID2_OFFSET = 0x14      # u32
UNKNOWN_1_OFFSET = 0x1C      # u32
MESSAGE_VERSION_OFFSET = 0x28  # u32
FLAGS_OFFSET = 0x34          # u8
SEND_METHOD_OFFSET = 0x35    # u8
UNOPENED_OFFSET = 0x36       # u8
NEW_FLAG_OFFSET = 0x37       # u8
SEND_COUNT_OFFSET = 0x6C     # u8
FORWARD_COUNT_OFFSET = 0x6D  # u8
USER_DATA_OFFSET = 0x6E      # u16

# body内のコメント欄・Mii blobの位置はゲーム
# ごとに異なりうるため、scripts/game_profiles.pyのGameProfileに切り出し
# 済み(comment_body_offset/comment_header_len/mii_blob_body_offset)。
# Mii Plaza自身の値はgame_profiles.MII_PLAZAを参照。

# body先頭64バイトの「ヘッダ/メタデータ」領域(調査結果、
# 2026-09-15に解析): offset 0のu64(LE)が3DSタイトルID、offset 8のu16(LE)が
# **そのタイトルの実際のTitleVersion**(実機NANDのTMD(title/00040010/.../
# content/*.tmd)のtitle_versionとビット単位で完全一致することを実証済み
# -- major<<10|minor<<4|micro、3dbrew記載の標準エンコーディングそのまま)、
# offset 48のUTF-16LE文字列(16バイト、NUL埋め)がそのタイトルの表示名、
# という3点セットだった。実データで確認: (0x0004001000020000, v12.0.1,
# "本体設定")、(0x0004001000020700, v2.1.0, "Miiスタジオ")。「送信者の
# "本体のMii"を最後に設定/更新したタイトルとそのバージョン」を指している
# という仮説だが、これが受理判定に使われているかは未確定。offset 10〜47の
# 38バイトは依然未解析(既知サンプルでは全てゼロ)。
BODY_HEADER_TITLE_ID_OFFSET = 0       # body先頭からのオフセット、8バイト(u64 LE)
BODY_HEADER_TITLE_VERSION_OFFSET = 8  # body先頭からのオフセット、2バイト(u16 LE、TMDのtitle_versionと同一エンコーディング)
BODY_HEADER_TITLE_NAME_OFFSET = 48    # body先頭からのオフセット、16バイト(UTF-16LE、NUL埋め)


class TmpBox:
    """TMP Box body(1ファイル分)を読み込み、各フィールドへの
    アクセス/書き換えを提供する薄いラッパー。"""

    def __init__(self, data: bytes, profile: GameProfile = DEFAULT_PROFILE):
        self.data = bytearray(data)
        self.profile = profile
        magic, _pad, self.message_size, self.total_header_size, self.body_size = \
            struct.unpack_from("<HHIII", self.data, 0)
        if magic != 0x6060:
            raise ValueError(f"not a TMP Box body (magic={magic:#06x}, expected 0x6060)")

    @classmethod
    def load(cls, path: Path, profile: GameProfile = DEFAULT_PROFILE) -> "TmpBox":
        return cls(path.read_bytes(), profile=profile)

    def save(self, path: Path) -> None:
        path.write_bytes(bytes(self.data))

    def _comment_body_offset(self) -> int:
        if self.profile.comment_body_offset is None:
            raise ValueError(f"{self.profile.name} has no known comment field location yet")
        return self.profile.comment_body_offset

    def _mii_blob_body_offset(self) -> int:
        if self.profile.mii_blob_body_offset is None:
            raise ValueError(f"{self.profile.name} has no known Mii blob location yet")
        return self.profile.mii_blob_body_offset

    # --- ヘッダID系フィールド ---
    def header_field(self, offset: int, length: int) -> bytes:
        return bytes(self.data[offset:offset + length])

    def set_header_field(self, offset: int, value: bytes) -> None:
        if len(value) != len(self.data[offset:offset + len(value)]):
            raise ValueError("length mismatch")
        self.data[offset:offset + len(value)] = value

    def randomize_ids(self) -> dict[str, tuple[bytes, bytes]]:
        """messageId/messageId2/batchId/senderId/senderId2/createdを
        ランダム化する(フォローアップ)。
        いずれもヘッダ部分(total_header_size未満)のフィールドで、HMAC
        トレーラーの対象範囲(body部分のみ)の外側にあるため、この操作
        単体ではトレーラー再計算は不要(が、他の変更と合わせて呼び出す
        場合は最後にrecompute_hmac()を呼ぶこと)。"""
        changes: dict[str, tuple[bytes, bytes]] = {}
        for name, offset, length in [
            ("messageId", MESSAGE_ID_OFFSET, 8),
            ("messageId2", MESSAGE_ID2_OFFSET, 8),
            ("batchId", BATCH_ID_OFFSET, 4),
            ("senderId", SENDER_ID_OFFSET, 8),
            ("senderId2", SENDER_ID2_OFFSET, 8),
        ]:
            old = self.header_field(offset, length)
            new = os.urandom(length)
            self.data[offset:offset + length] = new
            changes[name] = (old, new)

        old_created = self.header_field(CREATED_OFFSET, 12)
        new_created = _pack_timestamp(datetime.datetime.now())
        self.data[CREATED_OFFSET:CREATED_OFFSET + 12] = new_created
        changes["created"] = (old_created, new_created)
        return changes

    # --- 調査結果: 未検証フィールド群 ---
    _UNEXPLORED_FIELDS = [
        ("titleId2", TITLE_ID2_OFFSET, 4),
        ("unknown_1", UNKNOWN_1_OFFSET, 4),
        ("messageVersion", MESSAGE_VERSION_OFFSET, 4),
        ("flags", FLAGS_OFFSET, 1),
        ("sendMethod", SEND_METHOD_OFFSET, 1),
        ("unopened", UNOPENED_OFFSET, 1),
        ("newFlag", NEW_FLAG_OFFSET, 1),
        ("sendCount", SEND_COUNT_OFFSET, 1),
        ("forwardCount", FORWARD_COUNT_OFFSET, 1),
        ("userData", USER_DATA_OFFSET, 2),
    ]

    def get_unexplored_fields(self) -> dict[str, bytes]:
        return {name: self.header_field(offset, length)
                for name, offset, length in self._UNEXPLORED_FIELDS}

    def fuzz_unexplored_fields(self) -> dict[str, tuple[bytes, bytes]]:
        """project findings: titleId2/unknown_1/messageVersion/
        flags/sendMethod/unopened/newFlag/sendCount/forwardCount/userDataを
        一括でランダム値に書き換える。Mii blob・コメント本文は一切
        変更しないため、実機での受理/表示結果が変わらなければ「これらの
        フィールドは受理判定・表示に影響しない」ことの証拠になる
        (逆に拒否されれば、どれが効いているかを1つずつ切り分ける必要が
        ある)。いずれもヘッダ部分のフィールドのため、この操作単体では
        HMACトレーラー再計算は不要。"""
        changes: dict[str, tuple[bytes, bytes]] = {}
        for name, offset, length in self._UNEXPLORED_FIELDS:
            old = self.header_field(offset, length)
            new = os.urandom(length)
            self.data[offset:offset + length] = new
            changes[name] = (old, new)
        return changes

    # --- コメント欄 ---
    # 調査結果: 先頭u32フィールドは文字数ではないと実機で
    # 確認済み(16文字のコメントで14、「あ」1文字のコメントで23という、
    # 文字数と無関係な値が実測された。正体は依然不明)。代わりにNUL終端
    # (UTF-16LEの0x0000)を実際の文字列の境界として扱う——実機の2つの
    # 実キャプチャ双方でこの方式が正しいことを確認済み。
    _COMMENT_SCAN_MAX_CHARS = 256  # 暴走防止の上限(実測値は20文字未満)
    # 調査結果(2026-09-23確定): 実機のMii Plaza設定画面の
    # 自己紹介コメント入力欄自体が16文字までしか入力できないため、これを
    # 実機互換の上限として採用する。次の既知構造(body末尾のカウンタ領域、
    # offset 29044)まで12KB以上の未使用領域があるため、この程度の伸長は
    # 安全に書き込める。
    COMMENT_MAX_CHARS = 16
    _COMMENT_FIELD_CLEAR_BYTES = (COMMENT_MAX_CHARS + 1) * 2  # 文字列16+NUL終端分

    def get_comment(self) -> str:
        off = self.total_header_size + self._comment_body_offset()
        text_off = off + self.profile.comment_header_len
        chars = self.data[text_off:text_off + self._COMMENT_SCAN_MAX_CHARS * 2]
        nul = chars.find(b"\x00\x00")
        # UTF-16LEの1文字目バイトがたまたま0x00になるサロゲート等を
        # 避けるため偶数境界にそろえる
        if nul != -1 and nul % 2 != 0:
            nul = chars.find(b"\x00\x00", nul + 1)
        end = nul if nul != -1 else len(chars)
        return bytes(chars[:end]).decode("utf-16le")

    def set_comment(self, new_text: str) -> str:
        """コメント欄を書き換える。実機のMii Plaza入力画面自体が16文字
        までしか入力できないため、これを上限として採用する
        (調査結果、2026-09-23確定)。元の文字列の長さに
        関わらず、固定幅(16文字+NUL終端=34バイト、後続の既知構造まで
        12KB以上の余白があるため安全)をNUL埋めしてから新しい文字列+NUL
        終端を書き込む。"""
        if len(new_text) > self.COMMENT_MAX_CHARS:
            raise ValueError(
                f"コメントは{self.COMMENT_MAX_CHARS}文字以下でなければなりません"
                f"(実機Mii Plazaの入力欄自体の上限、指定されたのは"
                f"{len(new_text)}文字: {new_text!r})。"
            )
        old_text = self.get_comment()
        off = self.total_header_size + self._comment_body_offset()
        text_off = off + self.profile.comment_header_len
        new_bytes = new_text.encode("utf-16le")
        clear_len = self._COMMENT_FIELD_CLEAR_BYTES
        self.data[text_off:text_off + clear_len] = new_bytes + bytes(clear_len - len(new_bytes))
        return old_text

    def get_comment_length_field(self) -> int:
        off = self.total_header_size + self._comment_body_offset()
        return struct.unpack_from("<I", self.data, off)[0]

    # --- ヘッダのTLV拡張領域(調査結果、固定112バイトの
    # CecMessageHeaderに続く可変長領域、total_header_sizeまで) ---
    # 各エントリは (id: u32 LE, length: u32 LE, data: lengthバイト) の
    # 詰め物無しの連続。id=2は「最近遊んだソフト」のSMDHタイトルアイコン
    # データ(可変長、これがあるせいで後続エントリのオフセットは box ごとに
    # 変わる)、id=4がMii Plazaの定型通知メッセージ("誰か来ています!"、
    # §7.43で書き換えに成功済み)。offsetは実データで検証済み(2026-09-16)
    # ——ドキュメントに記載の固定オフセット(3340等)はこのTLV領域を
    # 手作業で1回だけ読んだ時の値にすぎず、box毎に変わるため、常にこの
    # ウォーカーで動的に探すこと。
    _HEADER_TLV_START = 112  # CecMessageHeader固定部分の直後
    NOTIFICATION_MESSAGE_TLV_ID = 4

    def _walk_header_tlv(self):
        """(id, data_offset, length)を順に返す。"""
        off = self._HEADER_TLV_START
        while off + 8 <= self.total_header_size:
            entry_id, length = struct.unpack_from("<II", self.data, off)
            data_off = off + 8
            if data_off + length > self.total_header_size:
                break  # 壊れたデータ、これ以上読まない
            yield entry_id, data_off, length
            off = data_off + length

    def _find_header_tlv(self, entry_id: int) -> tuple[int, int]:
        for eid, data_off, length in self._walk_header_tlv():
            if eid == entry_id:
                return data_off, length
        raise ValueError(f"TLV entry id={entry_id} not found in header (total_header_size={self.total_header_size})")

    def get_notification_message(self) -> str:
        """Mii Plazaの定型通知メッセージ("誰か来ています!"相当)。コメント欄と違い、この欄の長さ
        フィールドは実際の文字数(NUL終端込みのバイト数)と一致することを
        実データで確認済み。"""
        data_off, length = self._find_header_tlv(self.NOTIFICATION_MESSAGE_TLV_ID)
        raw = bytes(self.data[data_off:data_off + length])
        return raw.decode("utf-16le").rstrip("\x00")

    def set_notification_message(self, new_text: str) -> str:
        """定型通知メッセージを書き換える。set_comment()と同じ制約
        (新しい文字列は元と同じ文字数以下)。このTLV領域はHMACトレーラー
        の対象範囲(bodyのみ)の外側にあるため、この操作単体では
        recompute_hmac()は不要。"""
        data_off, length = self._find_header_tlv(self.NOTIFICATION_MESSAGE_TLV_ID)
        old_text = self.get_notification_message()
        if len(new_text) > len(old_text):
            raise ValueError(
                f"新しい通知メッセージは元の{len(old_text)}文字以下でなければ"
                f"なりません(指定されたのは{len(new_text)}文字: {new_text!r})。"
            )
        new_bytes = new_text.encode("utf-16le") + b"\x00\x00"
        self.data[data_off:data_off + length] = new_bytes + bytes(length - len(new_bytes))
        return old_text

    def set_comment_length_field(self, value: int) -> int:
        """調査結果の検証用: 可視文字列のバイト列は一切
        変更せず、先頭u32の「文字数」フィールドだけを任意の値に書き換える。
        実機がこのフィールドの値によって実際に表示する文字数がどう変わるか
        (無視されるのか、素直にvalue文字だけ表示するのか、value+2文字
        表示するのか等)を切り分けるための実験用。"""
        off = self.total_header_size + self._comment_body_offset()
        old = self.get_comment_length_field()
        struct.pack_into("<I", self.data, off, value)
        return old

    # --- 送信者Mii ---
    def get_mii_identity(self) -> MiiIdentity:
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = decode_mii_blob(blob)
        return MiiIdentity.from_ffl_store_data(mii)

    def set_raw_mii(self, ffl_store_data: bytes) -> None:
        """送信者Miiを、生の96バイトFFLStoreData(実機の他のセーブデータ
        から抽出した本物のMii等)に丸ごと差し替えてAES-CCM再暗号化する。
        CRC16チェックサムは差し替え元データのものをそのまま使う(既に
        正しいはずなので再計算はしない——別コンソール由来の本物データを
        変更せず使う用途を想定)。呼び出し後は必ずrecompute_hmac()も
        呼ぶこと(調査結果、console B実機データでの検証用、
        2026-09-15)。"""
        if len(ffl_store_data) != FFL_STORE_DATA_SIZE:
            raise ValueError(f"FFLStoreData must be exactly {FFL_STORE_DATA_SIZE} bytes, got {len(ffl_store_data)}")
        off = self.total_header_size + self._mii_blob_body_offset()
        new_blob = encode_mii_blob(ffl_store_data, recompute_checksum=False)
        self.data[off:off + TMP_BOX_MII_BLOB_LEN] = new_blob

    def randomize_author_id(self) -> tuple[bytes, bytes]:
        """送信者MiiのFFLStoreData(mii_id・顔・ニックネームはそのまま)の
        author_id(offset 0x04、8バイト、Miiを作成したコンソールのID)
        だけを新しい値に差し替え、CRC16チェックサムを再計算した上で
        AES-CCM再暗号化する(nonceはmii_id由来で不変のため、暗号文は
        author_idの位置だけ変わる)。調査結果:
        これまでの全テストでauthor_idは常に本物のまま変更しておらず、
        単独で書き換えたことが無かった
        ため、mii_idとは独立に検証する。"""
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = bytearray(decode_mii_blob(blob))
        old_id = bytes(mii[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + 8])
        new_id = os.urandom(8)
        mii[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + 8] = new_id
        new_blob = encode_mii_blob(bytes(mii))
        self.data[off:off + TMP_BOX_MII_BLOB_LEN] = new_blob
        return old_id, new_id

    def randomize_mii_id(self) -> tuple[bytes, bytes]:
        """送信者MiiのFFLStoreData(顔・ニックネームはそのまま)の
        mii_id(offset 0x0C、10バイト)だけを新しい値に差し替え、CRC16
        チェックサムを再計算した上でAES-CCM再暗号化する。実機での「別Mii」認識効果は
        調査結果参照(未確認)。"""
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = bytearray(decode_mii_blob(blob))
        old_id = bytes(mii[MII_ID_OFFSET:MII_ID_OFFSET + 10])
        new_id = new_mii_id()
        mii[MII_ID_OFFSET:MII_ID_OFFSET + 10] = new_id
        new_blob = encode_mii_blob(bytes(mii))
        self.data[off:off + TMP_BOX_MII_BLOB_LEN] = new_blob
        return old_id, new_id

    def set_identity(self, author_id: bytes, mii_id: bytes) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
        """送信者MiiのFFLStoreData(顔・ニックネームはそのまま)の
        author_id/mii_idを、指定した値(実機由来の本物の値等、ランダム
        生成ではない値)にそのまま差し替え、CRC16チェックサムを再計算した
        上でAES-CCM再暗号化する。調査結果(2026-09-17):
        「乱数生成したauthor_id/mii_idは常に拒否される」現象が、乱数生成
        特有の何らかの不備によるものか、それとも(本物の値であっても)
        Mii内容とidentityの組み合わせそのものへの検証によるものかを
        切り分ける実験用——本物だが別コンソール由来のauthor_id/mii_idを
        ここで指定して検証する。"""
        if len(author_id) != 8:
            raise ValueError(f"author_id must be exactly 8 bytes, got {len(author_id)}")
        if len(mii_id) != 10:
            raise ValueError(f"mii_id must be exactly 10 bytes, got {len(mii_id)}")
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = bytearray(decode_mii_blob(blob))
        old_author_id = bytes(mii[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + 8])
        old_mii_id = bytes(mii[MII_ID_OFFSET:MII_ID_OFFSET + 10])
        mii[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + 8] = author_id
        mii[MII_ID_OFFSET:MII_ID_OFFSET + 10] = mii_id
        new_blob = encode_mii_blob(bytes(mii))
        self.data[off:off + TMP_BOX_MII_BLOB_LEN] = new_blob
        return (old_author_id, author_id), (old_mii_id, mii_id)

    def set_mole_enable(self, enable: bool) -> tuple[int, int]:
        """送信者MiiのFFLStoreData中、`mole`フィールド(offset 0x46、u16 LE、
        docs/PROTOCOL_REFERENCE.md §9)のbit0(`enable`、2026-09-13訂正済み)
        だけを書き換え、CRC16チェックサムを再計算してAES-CCM再暗号化する。
        author_id/mii_id/nickname/その他の顔パーツは一切変更しない。

        調査結果: 「Mii本体データ全体を他人のMiiに差し替え」
        実験(author_id/mii_idごと変わって失敗)とは別に、「識別情報
        (author_id/mii_id)は完全に本物のまま維持し、顔パーツのビットだけ
        変える」という条件を単体で切り分けるための実験用(2026-09-16、
        提案)。"""
        MOLE_OFFSET = 0x46
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = bytearray(decode_mii_blob(blob))
        old_mole = struct.unpack_from("<H", mii, MOLE_OFFSET)[0]
        new_mole = (old_mole | 1) if enable else (old_mole & ~1)
        struct.pack_into("<H", mii, MOLE_OFFSET, new_mole)
        new_blob = encode_mii_blob(bytes(mii))
        self.data[off:off + TMP_BOX_MII_BLOB_LEN] = new_blob
        return old_mole, new_mole

    # --- HMACトレーラー ---
    def trailer_offset(self) -> int:
        return self.total_header_size + self.body_size

    def recompute_hmac(self) -> tuple[bytes, bytes]:
        """body部分(ヘッダを含まない)に対するHMAC-SHA256を再計算し、
        末尾32バイトのトレーラーに書き込む。
        body(コメント・Mii blob等)を書き換えた場合は必ず呼ぶこと。"""
        trailer_off = self.trailer_offset()
        message_body = bytes(self.data[self.total_header_size:self.total_header_size + self.body_size])
        new_trailer = hmac.new(self.profile.hmac_key, message_body, hashlib.sha256).digest()
        old_trailer = bytes(self.data[trailer_off:trailer_off + 32])
        self.data[trailer_off:trailer_off + 32] = new_trailer
        return old_trailer, new_trailer

    def verify_hmac(self) -> bool:
        trailer_off = self.trailer_offset()
        message_body = bytes(self.data[self.total_header_size:self.total_header_size + self.body_size])
        expected = hmac.new(self.profile.hmac_key, message_body, hashlib.sha256).digest()
        return bytes(self.data[trailer_off:trailer_off + 32]) == expected

    def verify_mii_checksum(self) -> bool:
        off = self.total_header_size + self._mii_blob_body_offset()
        blob = bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN])
        mii = decode_mii_blob(blob)
        stored = int.from_bytes(mii[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2], "big")
        return stored == crc16_xmodem(mii[:CHECKSUM_OFFSET])

    def verify_mii_tag(self) -> bool:
        """MiiブロックのCCMタグ(16バイト全体)を検証する。Mii Plazaは
        受信時にこれを検証し、不一致のMiiは黙って捨てる
        (project findings 2026-09-23)。"""
        off = self.total_header_size + self._mii_blob_body_offset()
        return verify_mii_blob_tag(bytes(self.data[off:off + TMP_BOX_MII_BLOB_LEN]))

    def get_body_header_title(self) -> tuple[int, int, str]:
        """調査結果: body先頭のtitleId(u64 LE)+
        titleVersion(u16 LE、TMDのtitle_versionと同一エンコーディング、
        実機NANDのTMDとビット単位で一致することを実証済み)+
        表示名(UTF-16LE、NUL埋め)の3点セットを取得する。"""
        base = self.total_header_size
        title_id = int.from_bytes(
            self.data[base + BODY_HEADER_TITLE_ID_OFFSET:base + BODY_HEADER_TITLE_ID_OFFSET + 8], "little")
        title_version = int.from_bytes(
            self.data[base + BODY_HEADER_TITLE_VERSION_OFFSET:base + BODY_HEADER_TITLE_VERSION_OFFSET + 2], "little")
        name_raw = bytes(self.data[base + BODY_HEADER_TITLE_NAME_OFFSET:base + BODY_HEADER_TITLE_NAME_OFFSET + 16])
        name = name_raw.decode("utf-16le", errors="replace").rstrip("\x00")
        return title_id, title_version, name

    def set_body_header_title(self, title_id: int, title_version: int, name: str) -> tuple[int, int, str]:
        """調査結果(2026-09-17): body先頭の「送信者の
        本体を最後に設定/更新したタイトル」情報を書き換える。console Bの
        本物Miiをテンプレート(console A由来)へ移植した際にここを直し
        忘れており、「console BのMii/識別情報を持つのにbody header title
        はconsole A自身」という実機ではあり得ない矛盾したBoxになっていた
        ——これがサイレント拒否の真因かを切り分ける実験用。"""
        base = self.total_header_size
        old = self.get_body_header_title()
        struct.pack_into("<Q", self.data, base + BODY_HEADER_TITLE_ID_OFFSET, title_id)
        struct.pack_into("<H", self.data, base + BODY_HEADER_TITLE_VERSION_OFFSET, title_version)
        name_bytes = name.encode("utf-16le")
        if len(name_bytes) > 16:
            raise ValueError(f"name {name!r} encodes to {len(name_bytes)} bytes, must fit in 16")
        name_off = base + BODY_HEADER_TITLE_NAME_OFFSET
        self.data[name_off:name_off + 16] = name_bytes + bytes(16 - len(name_bytes))
        return old


def _pack_timestamp(dt: datetime.datetime) -> bytes:
    weekday = (dt.weekday() + 1) % 7  # CTR week starts on Sunday=0
    return struct.pack("<IBBBBBBH", dt.year, dt.month, dt.day, weekday,
                        dt.hour, dt.minute, dt.second, dt.microsecond // 1000)


def cmd_show(args: argparse.Namespace) -> int:
    box = TmpBox.load(args.input, profile=get_profile(args.game))
    print(f"file:              {args.input}")
    print(f"message_size:      {box.message_size}")
    print(f"total_header_size: {box.total_header_size}")
    print(f"body_size:         {box.body_size}")
    print(f"title_id:          {int.from_bytes(box.header_field(0x10, 4), 'little'):#010x}")
    print(f"messageId:         {box.header_field(MESSAGE_ID_OFFSET, 8).hex()}")
    print(f"senderId:          {box.header_field(SENDER_ID_OFFSET, 8).hex()}")
    print(f"senderId2:         {box.header_field(SENDER_ID2_OFFSET, 8).hex()}")
    print(f"comment:           {box.get_comment()!r}")
    try:
        print(f"notification msg:  {box.get_notification_message()!r}")
    except ValueError as e:
        print(f"notification msg:  <not found: {e}>")
    body_title_id, body_title_version, body_title_name = box.get_body_header_title()
    v_major, v_minor, v_micro = (body_title_version >> 10) & 0x3F, (body_title_version >> 4) & 0x3F, body_title_version & 0xF
    print(f"body header title: id={body_title_id:#018x} version={v_major}.{v_minor}.{v_micro} "
          f"name={body_title_name!r}")
    print("unexplored fields:")
    for name, value in box.get_unexplored_fields().items():
        print(f"  {name:<15} {value.hex()}")
    try:
        identity = box.get_mii_identity()
        print(f"mii nickname:      {identity.nickname!r}")
        print(f"mii author_id:     {identity.author_id.hex()}")
        print(f"mii_id:            {identity.mii_id.hex()}")
        print(f"mii checksum ok:   {box.verify_mii_checksum()}")
        print(f"mii CCM tag ok:    {box.verify_mii_tag()}")
    except Exception as e:  # noqa: BLE001
        print(f"mii blob decode failed: {e}")
    print(f"outer HMAC valid:  {box.verify_hmac()}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    box = TmpBox.load(args.input, profile=get_profile(args.game))
    hmac_ok = box.verify_hmac()
    try:
        mii_ok = box.verify_mii_checksum()
        tag_ok = box.verify_mii_tag()
    except Exception:  # noqa: BLE001
        mii_ok = tag_ok = False
    print(f"outer HMAC:  {'OK' if hmac_ok else 'NG'}")
    print(f"Mii CRC16:   {'OK' if mii_ok else 'NG'}")
    print(f"Mii CCM tag: {'OK' if tag_ok else 'NG'}")
    return 0 if (hmac_ok and mii_ok and tag_ok) else 1


def cmd_edit(args: argparse.Namespace) -> int:
    box = TmpBox.load(args.input, profile=get_profile(args.game))

    if args.comment is not None:
        old = box.set_comment(args.comment)
        print(f"comment: {old!r} -> {args.comment!r}")

    if args.notification_message is not None:
        old = box.set_notification_message(args.notification_message)
        print(f"notification message: {old!r} -> {args.notification_message!r}")

    if args.comment_length_field is not None:
        old = box.set_comment_length_field(args.comment_length_field)
        print(f"comment length_field: {old} -> {args.comment_length_field} "
              f"(可視バイト列は変更していない、調査結果の検証用)")

    if args.new_ids:
        for name, (old, new) in box.randomize_ids().items():
            print(f"{name}: {old.hex()} -> {new.hex()}")

    if args.new_author_id:
        old, new = box.randomize_author_id()
        print(f"author_id: {old.hex()} -> {new.hex()}")

    if args.new_mii_id:
        old, new = box.randomize_mii_id()
        print(f"mii_id: {old.hex()} -> {new.hex()}")

    if args.set_identity is not None:
        author_id_hex, mii_id_hex = args.set_identity
        (old_a, new_a), (old_m, new_m) = box.set_identity(bytes.fromhex(author_id_hex), bytes.fromhex(mii_id_hex))
        print(f"author_id: {old_a.hex()} -> {new_a.hex()}")
        print(f"mii_id: {old_m.hex()} -> {new_m.hex()}")

    if args.set_mii_file is not None:
        raw = args.set_mii_file.read_bytes()
        box.set_raw_mii(raw)
        print(f"mii: 送信者Miiを{args.set_mii_file}(生のFFLStoreData、{len(raw)}バイト)に丸ごと差し替えた")

    if args.set_mole is not None:
        old, new = box.set_mole_enable(args.set_mole)
        print(f"mole field: {old:#06x} -> {new:#06x} (enable bit0={'1' if args.set_mole else '0'}、"
              "author_id/mii_id/nicknameは維持、調査結果切り分け用)")

    if args.body_header_title is not None:
        title_id_str, title_version_str, name = args.body_header_title
        old = box.set_body_header_title(int(title_id_str, 0), int(title_version_str, 0), name)
        print(f"body header title: {old} -> {(int(title_id_str, 0), int(title_version_str, 0), name)} "
              "(調査結果切り分け用)")

    if args.fuzz_unexplored_fields:
        for name, (old, new) in box.fuzz_unexplored_fields().items():
            print(f"{name}: {old.hex()} -> {new.hex()}")

    old_trailer, new_trailer = box.recompute_hmac()
    print(f"HMAC trailer: {old_trailer.hex()} -> {new_trailer.hex()}")

    box.save(args.output)
    print(f"wrote {args.output} ({len(box.data)} bytes)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    game_help = (f"対象ゲームのプロファイル(scripts/game_profiles.py、"
                 f"既知: {sorted(GAME_PROFILES)}。今のところMii Plaza専用の"
                 "解析結果しか無いが、他タイトルの解析が進めばここに追加できる)")

    p_show = sub.add_parser("show", help="内容を表示する(書き換えなし)")
    p_show.add_argument("input", type=Path)
    p_show.add_argument("--game", type=str, default="miiplaza", help=game_help)
    p_show.set_defaults(func=cmd_show)

    p_verify = sub.add_parser("verify", help="HMAC/CRC16の検証のみ行う")
    p_verify.add_argument("input", type=Path)
    p_verify.add_argument("--game", type=str, default="miiplaza", help=game_help)
    p_verify.set_defaults(func=cmd_verify)

    p_edit = sub.add_parser("edit", help="書き換えて別ファイルに保存する")
    p_edit.add_argument("input", type=Path)
    p_edit.add_argument("output", type=Path)
    p_edit.add_argument("--game", type=str, default="miiplaza", help=game_help)
    p_edit.add_argument("--comment", type=str, default=None,
                         help="新しいコメント全文(実機Mii Plazaの入力欄上限に合わせ16文字まで)")
    p_edit.add_argument("--notification-message", type=str, default=None,
                         help="Mii Plazaの定型通知メッセージ("
                              "「誰か来ています!」相当)"
                              "を書き換える(元と同じ文字数以下が必須)")
    p_edit.add_argument("--comment-length-field", type=int, default=None,
                         help="調査結果検証用: コメント欄先頭の"
                              "「文字数」フィールドだけを独立して書き換える"
                              "(可視バイト列は変更しない)")
    p_edit.add_argument("--new-ids", action="store_true",
                         help="messageId/messageId2/batchId/senderId/senderId2/createdをランダム化")
    p_edit.add_argument("--new-author-id", action="store_true",
                         help="送信者Miiのauthor_id(offset 0x04、8バイト、作成コンソールID)"
                              "だけを新規ランダム生成して再暗号化(mii_id/顔/ニックネームは維持、"
                              "調査結果: author_id単独での検証用、2026-09-15)")
    p_edit.add_argument("--new-mii-id", action="store_true",
                         help="送信者Miiのmii_idを新規生成して再暗号化(顔/ニックネームは維持)")
    p_edit.add_argument("--set-identity", nargs=2, metavar=("AUTHOR_ID_HEX", "MII_ID_HEX"), default=None,
                         help="送信者Miiのauthor_id(8バイト16進)/mii_id(10バイト16進)を指定した"
                              "任意の値に差し替える(顔/ニックネームは維持)。乱数生成ではなく"
                              "実機由来の本物の値を使う実験用(調査結果、2026-09-17)")
    p_edit.add_argument("--set-mii-file", type=Path, default=None,
                         help="送信者Miiを、生の96バイトFFLStoreDataファイルの内容に"
                              "丸ごと差し替える(他の実機のセーブデータから抽出した"
                              "本物のMii等を使う場合用)")
    p_edit.add_argument("--set-mole", type=lambda s: s.lower() in ("1", "true", "on", "yes"), default=None,
                         metavar="0|1",
                         help="送信者Miiの顔パーツ(mole = ほくろ、offset 0x46 bit0、"
                              "docs/PROTOCOL_REFERENCE.md §9)だけをON/OFFし、CRC16を"
                              "再計算(author_id/mii_id/nicknameは一切変更しない、"
                              "調査結果切り分け用、2026-09-16)")
    p_edit.add_argument("--body-header-title", nargs=3, metavar=("TITLE_ID", "TITLE_VERSION", "NAME"), default=None,
                         help="body先頭の「送信者の本体を最後に設定/更新したタイトル」情報"
                              "を書き換える。TITLE_IDは0x接頭辞の"
                              "16進数(u64)、TITLE_VERSIONは同じく0x接頭辞可(u16)、NAMEは"
                              "UTF-16LEで16バイト以内の文字列。他機のMiiを移植したテンプレートで"
                              "この値が移植元(元テンプレート)のまま矛盾していないか切り分ける用"
                              "(project findings、2026-09-17)")
    p_edit.add_argument("--fuzz-unexplored-fields", action="store_true",
                         help="調査結果検証用: titleId2/unknown_1/"
                              "messageVersion/flags/sendMethod/unopened/newFlag/"
                              "sendCount/forwardCount/userDataを一括ランダム化"
                              "(Mii blob・コメント本文は変更しない)")
    p_edit.set_defaults(func=cmd_edit)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

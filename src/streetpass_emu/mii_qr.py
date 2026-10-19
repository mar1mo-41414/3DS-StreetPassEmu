"""3DS Miiデータの暗号化フォーマット(QRコード / TMP Box内Mii blob共通)。

調査結果。TMP Box body内の「送信者Mii」ブロック(body offset
14036、108バイト)は、公式3DS Mii QRコードと全く同じフォーマットの先頭108
バイトである(実機QRコード4枚をzbarimgでデコードしたデータとTMP Boxの実
キャプチャをバイト比較して確認済み)。

鍵は全世界共通の固定値(コンソール固有ではない) -- 3dbrew "Mii Maker"、
https://gist.github.com/jaames/96ce8daa11b61b758b6b0227b55f9f78 より。

復号フォーマット:
    nonce(8B)       = blob[0:8]
    ciphertext(88B) = blob[8:96]
    plaintext88     = AES-CCM-decrypt(ciphertext, key, nonce + 4ゼロバイト)
    FFLStoreData(96B) = plaintext88[:12] + nonce + plaintext88[12:]
        (nonceは復号後、mii_idフィールドの一部として構造体中央に
        そのまま埋め戻される)
    QRコード本体・TMP Box body内のブロックとも nonce(8) + ciphertext(88)
    + CCM認証タグ(16) = 112バイト(0x70)。
    (2026-09-23訂正: 以前は「TMP Box内はタグ先頭12バイトのみの108バイト」
    と理解していたが誤り。body offset 14036はMii Plaza内蔵のMii DB
    (`CFPB`ヘッダ0x18バイト @ body 0x36bc)のエントリ0であり、エントリは
    0x70バイト。Mii PlazaはこれをAPT:Unwrap(in=0x70/out=0x60/
    nonceOffset=0xC)で復号し16バイトのタグ全体を検証する。実機の無改変
    Boxでは108バイトの直後4バイトがタグ末尾と一致することを確認済み。
    調査結果 2026-09-23参照)

    暗号化(encode_mii_blob)は復号の単純な逆にはならない -- CCMに渡す
    平文は88バイトではなく、末尾8バイトのゼロパディングを加えた96バイト
    全体である必要がある(参照実装:
    https://github.com/KestronProgramming/MiiJS の miiCrypto.js、元は
    kazuki-4ysのMiiInfoEditorCTR
    https://github.com/kazuki-4ys/kazuki-4ys.github.io/blob/148dc339974f8b7515bfdc1395ec1fc9becb68ab/web_apps/MiiInfoEditorCTR/encode.js
    に由来)。CTRモードのkeystreamはブロック単位で独立に計算されるため
    88バイトだけ暗号化しても先頭88バイトの暗号文はたまたま一致するが、
    CCM認証タグはメッセージ長全体(96 vs 88)に依存するため一致しない
    -- 2026-09-11、このズレが「Mii blobを変更すると実機に無視される」
    現象の原因の一つだったと判明・修正済み(実機Mii QRコード4枚全てで
    無改変の復号→再暗号化がバイト単位で完全一致することを確認)。

FFLStoreData構造体(96バイト、WUT/decaf-emu miidata.h準拠):
    0x00 (4B): バージョン等ビットフィールド
    0x04 (8B): author_id -- Miiを作成したコンソールのID
    0x0C (10B): mii_id (FFLCreateID: flags:4 + timestamp:28 (4B, LE)
                + deviceHash(6B))。deviceHashは実機のoriginal_macと同一値であることを確認済み。
                mii_idの先頭8バイトがAES-CCMのnonceとして再利用される
    0x1A (20B): mii_name (UTF-16LE、10文字)
    0x48 (20B): creator_name (UTF-16LE、10文字)
    0x5E (2B, ビッグエンディアン): checksum = CRC16/XMODEM(data[0:0x5E])

実機のMii QRコード4枚全てで、ニックネームのデコードとCRC16
チェックサムの一致を確認済み。

【2026-09-23 原因判明】mii_idや顔データを変更したブロックが実機に無視
されていたのは、旧実装が108バイトだけを書き換え、直後4バイト(タグ末尾)
に元のBoxの古い値を残していたため(Mii PlazaのUnwrapでタグ検証に失敗し、
該当Miiが黙って捨てられていた)。現在はタグ16バイトを含む112バイト全体を
書き換える。詳細は調査結果。
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from Crypto.Cipher import AES

QR_KEY = bytes([0x59, 0xFC, 0x81, 0x7E, 0x64, 0x46, 0xEA, 0x61,
                0x90, 0x34, 0x7B, 0x20, 0xE9, 0xBD, 0xCE, 0x52])

FFL_STORE_DATA_SIZE = 0x60  # 96
TMP_BOX_MII_BLOB_LEN = 112  # body offset 14036 の112バイト(CFPB DBエントリ0、タグ16バイト込み)
QR_CODE_RAW_SIZE = 112      # 実際のQRコードのバイナリペイロード(0x70)

AUTHOR_ID_OFFSET = 0x04
AUTHOR_ID_LEN = 8
MII_ID_OFFSET = 0x0C
MII_ID_LEN = 10  # nonce(先頭8B) + deviceHash後半2B
NICKNAME_OFFSET = 0x1A
NICKNAME_LEN = 20  # UTF-16LE 10文字
CREATOR_NAME_OFFSET = 0x48
CREATOR_NAME_LEN = 20
CHECKSUM_OFFSET = 0x5E


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM (poly=0x1021, init=0x0000, no reflect, no final XOR)。"""
    crc = 0x0000
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def decode_mii_blob(blob: bytes) -> bytes:
    """TMP Box body内の108バイトブロック(または112バイトの生QRデータの
    先頭108バイト以上)をFFLStoreData(96バイト)に復号する。"""
    if len(blob) < 96:
        raise ValueError(f"blob must be at least 96 bytes, got {len(blob)}")
    nonce = blob[0:8]
    ciphertext = blob[8:96]
    cipher = AES.new(QR_KEY, AES.MODE_CCM, nonce + bytes(4))
    plaintext88 = cipher.decrypt(ciphertext)
    return plaintext88[:12] + nonce + plaintext88[12:]


def encode_mii_blob(mii: bytes, recompute_checksum: bool = True) -> bytes:
    """FFLStoreData(96バイト)をTMP Box body用の112バイトブロック
    (nonce8 + ciphertext88 + タグ16、QRコードペイロードと同一)に
    再暗号化する。mii[12:20](mii_idの先頭8バイト)がAES-CCMのnonceとして
    再利用される -- これを変更すれば新しい(構造として正当な)Mii作成IDに
    なる。checksum(offset 0x5E)は自動的に再計算する。"""
    if len(mii) != FFL_STORE_DATA_SIZE:
        raise ValueError(f"FFLStoreData must be exactly {FFL_STORE_DATA_SIZE} bytes, got {len(mii)}")

    mii_arr = bytearray(mii)
    if recompute_checksum:
        crc = crc16_xmodem(bytes(mii_arr[:CHECKSUM_OFFSET]))
        mii_arr[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2] = crc.to_bytes(2, "big")
    mii = bytes(mii_arr)

    nonce = mii[12:20]
    # 調査結果で確認済み: 実際にCCMへ渡す平文は
    # 88バイトではなく、末尾に8バイトのゼロパディングを加えた96バイト
    # 全体(KestronProgramming/MiiJSのminiCrypto.js、元はkazuki-4ysの
    # MiiInfoEditorCTRのencode.jsに由来する実装と実機Mii QRコードのバイト
    # 比較で確認)。この8バイトを省いて88バイトだけを暗号化すると、暗号文
    # (先頭88バイト分)は偶然一致するがCCM認証タグは一致しない
    # (CTRモードの各ブロックのkeystreamは独立して計算されるため先頭88
    # バイトは影響を受けないが、タグはメッセージ長全体に依存するため)。
    plaintext_padded = mii[0:12] + mii[20:96] + bytes(8)
    cipher = AES.new(QR_KEY, AES.MODE_CCM, nonce + bytes(4), mac_len=16, msg_len=96)
    ciphertext96, tag = cipher.encrypt_and_digest(plaintext_padded)
    return nonce + ciphertext96[:88] + tag


def encode_mii_qr_payload(mii: bytes, recompute_checksum: bool = True) -> bytes:
    """実際の3DS Mii QRコードの生バイナリペイロード(112バイト)。
    TMP Box内のMiiブロックと同一フォーマットなのでencode_mii_blob()と同じ
    (調査結果のMii顔パーツ検証用に追加した名前を残している)。"""
    return encode_mii_blob(mii, recompute_checksum=recompute_checksum)


def verify_mii_blob_tag(blob: bytes) -> bool:
    """112バイトのMiiブロックのCCM認証タグ(16バイト全体)が正しいかを
    検証する。Mii Plazaが受信時に行うAPT:Unwrapのタグ検証に相当。"""
    if len(blob) < QR_CODE_RAW_SIZE:
        return False
    mii = decode_mii_blob(blob)
    return encode_mii_blob(mii, recompute_checksum=False) == bytes(blob[:QR_CODE_RAW_SIZE])


def new_mii_id(device_hash: bytes | None = None) -> bytes:
    """新しい(構造として正当な)mii_id(10バイト、avatar_id 4B + client_id/
    deviceHash 6B)を作る。

    【2026-09-13訂正】以前は先頭4バイトを「flags:4 + timestamp:28
    (リトルエンディアン)」として生成していたが、これは誤りだった —
    このflags/timestamp形式で生成したmii_idを実機のMiiメーカーにQR
    コードとして読ませたところ、外見データ・checksumとも正当であるにも
    関わらず「これはMiiのQRコードではありません」と拒否された(実機検証
    2026-09-13)。一方、有志のMii作成ツール
    kazuki-4ys/MiiInfoEditorCTR(https://github.com/kazuki-4ys/kazuki-4ys.github.io/blob/master/web_apps/MiiInfoEditorCTR/mii.js)
    が新規Mii作成時にavatar_idの**先頭バイトの上位4bitを常に0x9固定**
    (`0x90 + random(0,16)`、残り3バイトは完全ランダム)にしているのを
    見つけ、実機に保存されている本物のMiiのmii_idの先頭バイト
    も`0x9d`(上位nibble=0x9)だったことを確認した——このバイトパターンが
    Miiメーカー側の何らかの妥当性マーカー(バージョン/種別ビット)だと
    判断し、この生成規則に修正した。"""
    avatar_id = bytes([0x90 | secrets.randbelow(16)]) + os.urandom(3)
    dh = device_hash if device_hash is not None else os.urandom(6)
    if len(dh) != 6:
        raise ValueError("device_hash must be 6 bytes")
    return avatar_id + dh


@dataclass(frozen=True)
class MiiIdentity:
    """decode_mii_blob()の結果から読みやすい形で識別フィールドを取り出す。"""

    author_id: bytes
    mii_id: bytes
    nickname: str

    @classmethod
    def from_ffl_store_data(cls, mii: bytes) -> "MiiIdentity":
        nickname = mii[NICKNAME_OFFSET:NICKNAME_OFFSET + NICKNAME_LEN].decode(
            "utf-16le", errors="replace").rstrip("\x00")
        return cls(
            author_id=bytes(mii[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + AUTHOR_ID_LEN]),
            mii_id=bytes(mii[MII_ID_OFFSET:MII_ID_OFFSET + MII_ID_LEN]),
            nickname=nickname,
        )

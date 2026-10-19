# プロトコルリファレンス(現時点での確定事項)

このファイルは、これまでの調査で**現時点で確定していること**だけをまとめた、
実装の参照用ドキュメント。調査の経緯・失敗談は含めない。

できること/できないこと/未解決の課題は [STATUS.md](STATUS.md) にまとめてある。

## 目次

1. [層構造とファイル対応](#1-層構造とファイル対応)
2. [通信フロー](#2-通信フロー)
3. [CCMP暗号化と鍵導出](#3-ccmp暗号化と鍵導出)
4. [802.11管理フレーム](#4-80211管理フレーム)
5. [SPTCP(トランスポート層)](#5-sptcpトランスポート層)
6. [SPMTP(メッセージ層)のパケット一覧](#6-spmtpメッセージ層のパケット一覧)
7. [TMP Box(すれちがいメッセージ本体)の構造](#7-tmp-boxすれちがいメッセージ本体の構造)
8. [HMACトレーラー](#8-hmacトレーラー)
9. [Mii QRコード / FFLStoreData暗号化フォーマット](#9-mii-qrコード--fflstoredata暗号化フォーマット)
10. [必要な秘密情報・鍵一覧](#10-必要な秘密情報鍵一覧)

---

## 1. 層構造とファイル対応

| 層 | ファイル | 内容 |
|---|---|---|
| 802.11物理/管理フレーム | `src/streetpass_emu/dot11.py` | Probe Request/Response、Nintendo Vendor IE、管理フレームヘッダ |
| WPA2 CCMP暗号化 | `src/streetpass_emu/ccmp.py` | 802.11 Data frame⇔平文の暗号化/復号(AES-CCM) |
| CCMP鍵導出 | `src/streetpass_emu/crypto.py`, `keyscrambler.py`, `keyslot_2e.py`, `oracle.py` | Hash Block組立→HMAC-SHA1→AES-CTR |
| SPTCP(トランスポート層) | `src/streetpass_emu/sptcp.py` | レイヤー2版TCP相当、3-wayハンドシェイク、セグメント化 |
| SPMTP(メッセージ層) | `src/streetpass_emu/spmtp.py` | Identity/ModuleFilter/FriendCode/MessageBox/TmpBoxパケット |
| Mii QR/FFLStoreData | `src/streetpass_emu/mii_qr.py` | 送信者Miiの暗号化フォーマット(§9) |
| 状態機械 | `src/streetpass_emu/session.py` | `StreetPassResponder`。ハードウェア非依存のpure function |
| ハードウェアI/F | `src/streetpass_emu/driver_bridge.py` | wifit3の`WlanInterface`を抽象化 |
| 応用データ | `mii.py`, `smdh.py`, `recently_played.py`, `friend_code.py` | Mii/SMDH/最近遊んだソフト等の構造 |
| 実機テスト用スクリプト | `scripts/live_streetpass_test.py`, `scripts/streetpass_loop.py`, `scripts/mii_plaza_editor.py` | 下記「必要なツール」参照 |

USB WiFiアダプタとの通信は `tools/wifit3`(derv82/wifit3、GPLv2、gitignore対象、
本リポジトリにはコミットしない)のユーザーランドドライバ経由。OSのWiFiスタックを
完全に迂回してUSBチップのレジスタ/ファームウェアへ直接アクセスするため、
802.11の認証/アソシエーションを前提とする通常のAPモード抽象化(hostapd等)が
不要になる。詳細は `docs/MONITOR_MODE.md`。

## 2. 通信フロー

実機で確認済みの全ステップ:

1. 相手のブロードキャストProbe Request(SSID `Nintendo_3DS_continuous_scan_000`、
   Nintendo Vendor IE付き)を検知 → 相手のconsoleIDを記録、ユニキャストProbe
   Responseを返信
2. 相手からユニキャストProbe Request(宛先=自分のMAC、SSID空、Nintendo Tag
   なし)を受信 → 2回目のProbe Responseを返信
3. 直後、相手から保護802.11 Data frame(CCMP)が届き始める
4. **SPTCP 3-wayハンドシェイク(SYN→SYN+ACK→ACK)は、SPMTPメッセージを
   送るたびに毎回必要**(セッションに1回ではない。)
5. SPMTP Infoフェーズ: 固定順序
   `0x41→0x42→0x43→0x43→0x11→0x12→0x21→0x22→0x23→0x24→0x31→0x32→0x33→0x34→0x81→0x81`
   (client/master交互、§6参照)
6. Message Box SPMTPフェーズ: 実際のTMP Boxを、SPTCPのセグメント化転送
   (ウィンドウサイズ `0x38b8`)で転送(受信・送信とも実装・実機確認済み)
7. 双方送るものが無くなったら `ACK+FIN`→`ACK+FIN`→`ACK` で会話終了

## 3. CCMP暗号化と鍵導出

使用箇所: 手順3以降の全ての802.11 Data frame(`ccmp.py`、AES-CCM、MIC=8バイト、
EXT_IVフラグあり)。

鍵導出パイプライン(`crypto.py`):

1. **Hash Block**組立: `host_console_id(8B) + client_console_id(8B) + host_mac(6B)
   + client_mac(6B)` = 0x1Cバイト。"host"=Probe Responseを送った側(自分)、
   "client"=ブロードキャストProbe Requestを送ってきた側(相手)
2. `HMAC-SHA1(key=HMAC_KEY_RETAIL_CANDIDATE, hash_block)`
   — 鍵 = `b"Fsd33nrQdg0na29l\x00"`(17バイト、CECDバイナリ静的解析+実機2台の
   バイナリ一致+実トラフィックMIC検証で確定。全世界共通の固定値、コンソール
   固有ではない)
3. digest先頭16バイトをAES-CTRのカウンタとして使用
4. **keyslot 0x2E**("StreetPass"、PS moduleのKeyType 6)のNormalKeyでAES-CTR
   暗号化 → 出力16バイトがCCMP鍵
   - `normal_key = rol(rol(keyX,2,128) XOR keyY + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87, 128)`
     (`keyscrambler.py`、pyctrの`keygen_manual`と一致する公開の式)
   - KeyX/KeyYは実機固有(GodMode9でダンプ、§10参照)

3つの独立したテストベクタ(実キャプチャ2件+ホームブリューオラクルのテスト
ベクタ)で完全一致を確認済み。

## 4. 802.11管理フレーム

- Probe Request/Response: `dot11.py`の`parse_probe_request`/`parse_probe_response`/
  `build_probe_response`
- Nintendo Vendor Specific IE: OUI `00:1f:32`、type `0x01`(`dot11.build_nintendo_tag`)
- Action frame(category `0x7f`、OUI `00:1f:32`): **未実装**(送受信自体を実装
  していない。ペイロード構造は)

## 5. SPTCP(トランスポート層)

ヘッダ(`sptcp.py`、0x18=24バイト):

| オフセット | サイズ | フィールド | 値/備考 |
|---|---|---|---|
| 0x0 | 2 | magic | `0x5959` |
| 0x2 | 2 | total_size | header(0x18)+payload+0x18 |
| 0x4 | 4 | constant | `AD DE AF BE`(バイト列そのまま) |
| 0x8 | 4 | bytes_sent | **転送全体を通じた累積送信バイト数**(ウィンドウ相対ではない) |
| 0xC | 4 | bytes_received | **転送全体を通じた累積受信バイト数** |
| 0x10 | 1 | shifted_size | `(0x18+0x18)>>2` = 常に`0x0c`固定 |
| 0x11 | 1 | flags | FIN(bit0)/SYN(bit1)/RST(bit2)/PSH(bit3)/ACK(bit4)/END(bit5) |
| 0x12 | 2 | max_buffer_size | デフォルト`0x38b8`(LE格納で`b8 38`) |
| 0x14 | 4 | padding | 全ゼロ |

平文には `MSDU_PREAMBLE = aa aa 03 00 00 00 08 00 + 00 00`(802.2 LLC/SNAP風
10バイト)がSPTCPヘッダの前に付く。

## 6. SPMTP(メッセージ層)のパケット一覧

### ハンドシェイクヘッダ(0x10=16バイト)

| オフセット | サイズ | フィールド |
|---|---|---|
| 0x0 | 2 | magic = `0x6363` |
| 0x2 | 2 | padding |
| 0x4 | 4 | packet_type |
| 0x8 | 4 | ゼロ |
| 0xC | 4 | content_size |

PacketType: `IDENTITY_CLIENT=0x41` / `IDENTITY_MASTER=0x42` / `IDENTITY_ACCEPT=0x43` /
`MODULE_FILTER_CLIENT=0x11` / `MODULE_FILTER_MASTER=0x12` /
`FRIEND_CODE_CLIENT=0x21` / `FRIEND_CODE_MASTER=0x22` /
`FRIEND_FLAG_CLIENT=0x23` / `FRIEND_FLAG_MASTER=0x24` /
`MESSAGE_BOX_METADATA_LIST_CLIENT=0x31` / `_MASTER=0x32` /
`MESSAGE_BOX_METADATA_PARSED_CLIENT=0x33` / `_MASTER=0x34` /
`TMP_BOX_METADATA_LIST=0x81`(client/master同一値)

### IdentityPacket(0x41/0x42、SIZE=0x28=40バイト)

| オフセット | サイズ | フィールド | 検証状況 |
|---|---|---|---|
| 0x00 | 8 | transferable_id | 実機確認済み。Mii Plazaセーブデータに永続化された固定値(セッション毎ランダムではない) |
| 0x08 | 8 | unknown_8 | 意味不明(未解決。STATUS.md参照) |
| 0x10 | 4 | session_id | セッション毎ランダム |
| 0x14 | 6 | original_mac | 継続スキャンMACとは別物。CFL_DB内に固定値として実在確認 |
| 0x1A | 2 | padding | |
| 0x1C | 12 | timestamp | 先頭4バイトのみ確認済み: year(u16 LE)+2バイトゼロ+month(u8)+day(u8) |

### FriendCodePacket(0x21/0x22、8バイト)

64bit値。高32bit=チェックサム(`principal_id_checksum`=SHA1(principal_id LE
4B)[0]の上位7bit)、低32bit=principal ID。`spmtp.friend_code_value_from_string()`
で12桁の表示形式(例`4126-2228-0312`)と相互変換できる。

### FriendFlagPacket(0x23/0x24、4バイト)

相手がフレンドリストにいるかのフラグ。

### MessageBoxMetadataEntry(0x31-0x34、SIZE=0x20=32バイト)

| オフセット | サイズ | フィールド |
|---|---|---|
| 0x00 | 4 | title_id |
| 0x04 | 1 | send_mode |
| 0x05 | 1 | flag |
| 0x06 | 2 | send_state — 相手が0x33/0x34で書き換えて返す値。`1`で実際のTMP Box転送が起動することを実証済み |
| 0x08 | 4 | send_size |
| 0x0C | 4 | message_count |
| 0x10 | 16 | 未使用/予約(ゼロ埋め) |

### TmpBoxMetadataEntry(0x81、SIZE=8バイト)

`title_id(4B) + size(4B)`。全体は`count(4B) + entries`。実機は非空リストを
24スロット固定(`TMP_BOX_METADATA_LIST_SLOT_COUNT=24`)にゼロパディングして送る。

### TmpBoxHeader(TMP Box全体の先頭、TMP_BOX_MAGIC=`0x6161`、0x14=20バイト)

`magic(2B) + padding(2B) + size(4B) + title_id(4B) + group_id(4B) + message_count(4B)`。

## 7. TMP Box(すれちがいメッセージ本体)の構造

`TmpBoxHeader`の直後、"body"として渡ってくるデータ(`--outbound-tmp-box-body`
やcompleted_tmp_boxesが扱う単位)は、以下の`CecMessageHeader`(固定112バイト)
から始まる。

### CecMessageHeader(112バイト、magic=`0x6060`)

`NarcolepticK/libctru-cecd`の`cecApi.h`定義と実データ照合で解明:

```c
u16 magic;            // 0x00, = 0x6060
u16 padding;          // 0x02
u32 messageSize;      // 0x04, 全体サイズ(実測32692)
u32 totalHeaderSize;  // 0x08, ヘッダ全体長(実測3348)
u32 bodySize;         // 0x0C, body長(実測29312)
u32 titleId;          // 0x10, 例: 0x00020800 (Mii Plaza)
u32 titleId2;         // 0x14
u32 batchId;          // 0x18
u32 unknown_1;        // 0x1C
u8  messageId[8];     // 0x20 -- 再送時に同じ値だと「既受信」扱いで重複排除される
u32 messageVersion;   // 0x28
u8  messageId2[8];    // 0x2C
u8  flags;            // 0x34
u8  sendMethod;       // 0x35
u8  unopened;         // 0x36
u8  newFlag;          // 0x37
u64 senderId;         // 0x38
u64 senderId2;        // 0x40
CecTimestamp sent;     // 0x48 (12B)
CecTimestamp received; // 0x54 (12B)
CecTimestamp created;  // 0x60 (12B)
u8  sendCount;         // 0x6C
u8  forwardCount;      // 0x6D
u16 userData;          // 0x6E
```

`CecTimestamp` = `year:u32 + month:u8 + day:u8 + weekDay:u8 + hour:u8 + minute:u8
+ second:u8 + ms:u16`(`<IBBBBBBH`、12バイト)。

`0x70`以降〜`totalHeaderSize`(実測3348)まではTLV(Tag-Length-Value)列:
`[id:u32][size:u32][data:sizeバイト、4バイト境界パディング]`。実データで確認済みの
`id`は2種類:

- `id=0x4`: あいさつメッセージ、UTF-16LE(書き換え・実機表示反映を確認済み)
- `id=0x2`, size=3200: 送信元タイトルのアイコン画像(RGB565、40×40、PICA200
  GPU標準の8×8 Z-orderタイル)

### body(offset = `totalHeaderSize`、実測29312バイト)

| body内offset | サイズ | 内容 |
|---|---|---|
| 0x0000 (0) | 8B | タイトルID(u64 LE)。offset 8のバージョン・offset 48の表示名とセット(下記、2026-09-15) |
| 0x0008 (8) | 2B | 上記タイトルの**TitleVersion**(u16 LE、`major<<10|minor<<4|micro`)。実機NANDのTMD(`title/00040010/.../content/*.tmd`)の`title_version`とビット単位で一致することを実証済み |
| 0x000A〜0x002F (10〜47) | 38B | 詳細未解析(既知サンプルでは全てゼロ) |
| 0x0030 (48) | 16B | 上記タイトルIDの表示名(UTF-16LE、NUL埋め)。実例: `"本体設定"`(v12.0.1)/`"Miiスタジオ"`(v2.1.0) |
| 0x0040〜0x2038 | — | ほぼ全ゼロ(予約) |
| 0x2038 (8248) | 1152B | 小アイコン、24×24、RGB565、Z-orderタイル |
| 0x24B8 (9400) | 4608B | 大アイコン、48×48、同フォーマット |
| 0x36B8〜 | — | 大部分ゼロ |
| 0x36BC (14012) | 24B | Mii Plaza内蔵Mii DBのヘッダ。magic `"CFPB"`(retail。devは`"CFPN"`)、+0x14にエントリ数(実データは1)。Mii Plazaは受信時にmagicを検証する(2026-09-23) |
| 0x36D4 (14036) | 112B | **送信者Miiの暗号化ブロック**(Mii DBのエントリ0、タグ16バイト込み。§9参照) |
| 0x37A0 (14240) | 64B×15 | 国名ローカライズ文字列テーブル(UTF-16LE、15言語) |
| 0x3B60 (15200) | 2B×16 | 対応する内部国/地域コード値(実データは全て`0x2014`固定) |
| 0x3F60 (16224) | 16B+文字列 | **自己紹介コメント欄**(下記) |
| 29044〜29200 | 157B | カウンタ/実績値らしき数値列。**独立した4件の実キャプチャ(9/10〜9/15、5日間)でbyte単位で完全に不変**——送信ごとに変わるper-message/per-Mii識別データではなく、送信元コンソールのローカルな使用統計(歩数/Play Coin/内蔵ミニゲーム累積時間等)のスナップショットの可能性が高い |

### 自己紹介コメント欄(body offset 16224)

```
+0x00 (4B): u32 unk_field  -- 文字数ではない(下記参照)
+0x04 〜 +0x0F: 予約(12バイト、非ゼロの値が入っていることを確認済み、未解読)
+0x10〜: UTF-16LE文字列、NUL終端(0x0000)
```

**2026-09-11、実機の2件のキャプチャで確定**: `+0x00`のu32フィールドは
**文字数ではない**(コメント`"R8だぞ、Switch2遊べよ。"`(16文字)で14、
`"あ"`(1文字)で23——文字数と無関係な値が実測された。正体は不明、詳細は
)。**実際の可視文字列の境界はNUL終端
(UTF-16LEの0x0000)で正しく判定できる**ことを両キャプチャで確認済み。

可変長化は2026-09-11に部分的に解決: **元より短くする書き換えは実装済み**
(`scripts/mii_plaza_editor.py`、NUL終端方式により後続領域のオフセットを
一切変えずに済む)。元より長くする拡張は、この欄の本当の最大容量が不明
なため未対応。

## 8. HMACトレーラー

TMP Box bodyの末尾、`bodySize`の内訳には現れないが`messageSize`合計には
含まれる「隠れた」32バイト領域:

- 位置: `body全体[totalHeaderSize + bodySize : +32]`
- アルゴリズム: **HMAC-SHA256**
- 鍵: `b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl"`(32バイトASCII固定文字列。
  **Mii Plazaタイトル固有の全世界共通固定値であり、コンソール固有鍵ではない**。
  AzaharPlus上でのGDB動的解析+AzaharPlus本体のソース
  (`core/hle/service/cecd/cecd.cpp`の`Module::Interface::WriteMessageWithHMAC`)
  の直読で特定、実機キャプチャ2件で完全一致を確認済み)
- 対象範囲: **`body[totalHeaderSize : totalHeaderSize+bodySize]`(ヘッダ部分を
  含まない、body部分のみ)**

参考実装(`Crypto.Cipher`不要、標準ライブラリのみ):

```python
import hashlib, hmac
key = b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl"
trailer = hmac.new(key, body[header_size:header_size+body_size], hashlib.sha256).digest()
```

このHMACはbody内の**どのバイトを書き換えても**(コメント・送信者Miiブロック
含め)正しく再計算すれば通る。header部分(CecMessageHeaderの各ID系フィールド
含む)はこのHMACの対象範囲外なので、自由に変更してよい。

## 9. Mii QRコード / FFLStoreData暗号化フォーマット

TMP Box body offset 14036の**112バイト**ブロックは、**公式3DS Mii QRコードと
全く同じフォーマット**(実機のMii QRコード4枚をzbarimgでデコードしたデータと
TMP Boxの実キャプチャをバイト比較して確認済み)。

鍵は全世界共通の固定値(3dbrew "Mii Maker"、
[gist](https://gist.github.com/jaames/96ce8daa11b61b758b6b0227b55f9f78)より):

```
key = 59 FC 81 7E 64 46 EA 61 90 34 7B 20 E9 BD CE 52  (AES-128)
```

復号手順:

```
nonce(8B)       = blob[0:8]
ciphertext(88B) = blob[8:96]
plaintext88     = AES-CCM-decrypt(ciphertext, key, nonce + 4ゼロバイト)
FFLStoreData(96B) = plaintext88[:12] + nonce + plaintext88[12:]
```

QRコード・TMP Box内ブロックとも112バイト(nonce8+ciphertext88+CCM認証タグ16)。
**2026-09-23訂正**: 以前は「TMP Box内はタグ先頭12バイトのみの108バイト」と
していたが誤りで、直後の4バイトがタグの残り4バイトだった(無改変の実機Box
3件で、16バイトのタグ全体が再計算値と一致することを確認)。Mii Plazaは
このブロックをAPT:Unwrap(`0x00470104`、in=0x70/out=0x60/nonceOffset=0xC)
で復号し**タグ16バイト全体を検証**するため、108バイトだけ書き換えると
タグ不一致で黙って破棄される。

**【解決済み】認証タグの正しい計算方法**: 当初pycryptodomeで88バイトの
平文に対しCCM暗号化・タグ計算を試みたところ、暗号文(keystream)は実機と
一致するのにタグだけ再現できなかった。原因は
[`KestronProgramming/MiiJS`](https://github.com/KestronProgramming/MiiJS)
(`miiCrypto.js`、実装は
[kazuki-4ysのMiiInfoEditorCTR](https://github.com/kazuki-4ys/kazuki-4ys.github.io/blob/148dc339974f8b7515bfdc1395ec1fc9becb68ab/web_apps/MiiInfoEditorCTR/encode.js)
に由来)の実装との突き合わせで判明: **CCMに渡す平文は88バイトではなく、
末尾8バイトのゼロパディングを加えた96バイト全体**である必要がある。

```
plaintext96 = mii[0:12] + mii[20:96] + 8バイトのゼロパディング
ciphertext96, tag16 = AES-CCM-encrypt(plaintext96, key, nonce+4ゼロバイト, mac_len=16, msg_len=96)
blob(112B) = nonce(8B) + ciphertext96[:88] + tag16
```

(CTRモードの各ブロックのkeystreamはブロック単位で独立に計算されるため、
末尾8バイトを省いても暗号文の先頭88バイトはたまたま一致してしまうが、
CCM認証タグはメッセージ長全体(96 vs 88)に依存するため一致しなかった)。
実機Mii QRコード4枚全てで、無改変での復号→再暗号化がバイト単位で完全に
元と一致することを確認済み(2026-09-11)。

### FFLStoreData構造体(96バイト、WUT/decaf-emu `miidata.h`準拠)

| offset | サイズ | フィールド |
|---|---|---|
| 0x00 | 4B | バージョン等ビットフィールド |
| 0x04 | 8B | `author_id` — Miiを作成したコンソールのID |
| 0x0C | 10B | `mii_id`(`avatar_id` 4B + `client_id`/deviceHash 6B)。deviceHashは実機の`original_mac`と一致確認済み。**先頭8バイトがAES-CCMのnonceとしてそのまま再利用される**。**2026-09-13訂正**: 先頭4バイトは「flags:4+timestamp:28」ではなく、**先頭バイトの上位4bitが常に`0x9`固定**(残り28bitはほぼ自由)というのが実際の生成規則だった —実機に保存されている本物のmii_id先頭バイトが`0x9d`だったことと、`kazuki-4ys/MiiInfoEditorCTR`の生成コード(`0x90 + random(0,16)`)から確認済み。この制約を満たさない`mii_id`をQRコードとして実機に読ませると「これはMiiのQRコードではありません」と拒否される(`mii_qr.new_mii_id()`で修正済み) |
| 0x1A | 20B | `mii_name`(UTF-16LE、10文字) |
| 0x48 | 20B | `creator_name`(UTF-16LE、10文字) |
| 0x5E | 2B(BE) | `checksum` = CRC16/XMODEM(`data[0:0x5E]`) |

実装は `src/streetpass_emu/mii_qr.py`(`decode_mii_blob`/`encode_mii_blob`/
`new_mii_id`/`MiiIdentity`)。実機Mii QRコード4枚全てでニックネームの
デコードとCRC16チェックサムの一致を確認済み。

### 顔パーツ等ビットフィールド(実機確認済み)

上表(author_id/mii_id/mii_name/creator_name/checksum)以外の残りの
バイト範囲(0x2E〜0x47)の詳細レイアウト。出典は
[`kazuki-4ys/mii2studio`](https://github.com/kazuki-4ys/mii2studio)の
Kaitai Structスペック
[`gen2_wiiu_3ds_miitomo.ksy`](https://github.com/kazuki-4ys/mii2studio/blob/main/gen2_wiiu_3ds_miitomo.ksy)
(3DS/WiiU/Miitomo世代共通のMiiフォーマット)。実機QRコード経由での検証
(体型・髪型・髪色・メガネ・ひげをまとめて変更 → 実機のMiiメーカーで
正しく反映)で大部分を確認済み。`mole`の`enable`ビットだけ、当初の想定
(bit15)が誤りだった——実機で手動で「ほくろ」を追加保存したMiiのQR
コードを解析し、`size`/`horizontal`/`vertical`の各ビットは完全一致する
一方、変化したビットが実際にはbit0だったことを確認して修正した(下表は
修正後)。

| offset | サイズ | フィールド |
|---|---|---|
| 0x2E | 1B | `body_height` |
| 0x2F | 1B | `body_weight` |
| 0x30 | 1B | `face_color`:3(bit7-5) + `face_type`:4(bit4-1) + `mingle`:1(bit0) |
| 0x31 | 1B | `face_makeup`:4(bit7-4) + `face_wrinkles`:4(bit3-0) |
| 0x32 | 1B | `hair_type`(まるごと1バイト) |
| 0x33 | 1B | `unknown_5`:4(bit7-4) + `hair_flip`:1(bit3) + `hair_color`:3(bit2-0) |
| 0x34 | 4B(LE u32) | `eye`: `type`=bit0-5, `color`=bit6-8, `size`=bit9-11, `stretch`=bit13-15, `rotation`=bit16-20, `horizontal`=bit21-24, `vertical`=bit25-29 |
| 0x38 | 4B(LE u32) | `eyebrow`: `type`=bit0-4, `color`=bit5-7, `size`=bit8-11, `stretch`=bit12-14, `rotation`=bit16-19, `horizontal`=bit21-24, `vertical`=bit25-29 |
| 0x3C | 2B(LE u16) | `nose`: `type`=bit0-4, `size`=bit5-8, `vertical`=bit9-13 |
| 0x3E | 2B(LE u16) | `mouth`: `type`=bit0-5, `color`=bit6-8, `size`=bit9-12, `stretch`=bit13-15 |
| 0x40 | 2B(LE u16) | `mouth2`: `mouth_vertical`=bit0-4, `facial_hair_mustache`=bit5-7 |
| 0x42 | 2B(LE u16) | `beard`: `facial_hair_beard`=bit0-2, `facial_hair_color`=bit3-5, `facial_hair_size`=bit6-9, `facial_hair_vertical`=bit10-14 |
| 0x44 | 2B(LE u16) | `glasses`: `type`=bit0-3, `color`=bit4-6, `size`=bit7-10, `vertical`=bit11-14 |
| 0x46 | 2B(LE u16) | `mole`: `size`=bit1-4, `horizontal`=bit5-9, `vertical`=bit10-14, `enable`=**bit0**(2026-09-13訂正、当初bit15としていたのは誤り)。bit15は未使用/常に0と思われる |

**注意(2026-09-23解決)**: 以前は「`mii_id`差し替え・本物の別人Miiの埋め込み等、
このブロックを変更すると実機に無視される」という未解決問題があったが、原因は
旧実装が108バイトしか書き換えず、タグ末尾4バイトに元のBoxの値が残っていたこと
だった(Mii Plaza側のタグ検証で破棄)。`mii_plaza_editor.py verify`で
`Mii CCM tag`を確認できる。詳細は。

### CFL_DB.dat(実機のMiiデータベース本体)の構造(2026-09-23確定)

実機の共有extdata`f000000b`(`extdata/00048000/f000000b/00000000/00000005`)の実体は、以下の単純な固定長テーブル:

```
offset 0x00〜0x07: ファイルヘッダ(8バイト、詳細未解析)
offset 0x08〜:     MiiOfficial(mii.py、0x5C=92バイト)がスロット単位で
                   連続配置(スロット間のパディング無し)
```

未使用スロットは`0xff 0x7f`の反復パターンで埋められている(UTF-16LEで
デコードすると`U+7FFF`(`翿`)の連続に化けるため、有効なMiiと誤認しない
よう`mii_name`にこの文字を含むスロットは除外すること)。

`scripts/extract_console_miis.py`でこのテーブルから有効なMiiエントリを
列挙し、任意のエントリを96バイトのFFLStoreData(`--set-mii-file`で使える
形式)として書き出せる。実機の生TMP Box(他人の本物のキャプチャ)から
`mii_qr.decode_mii_blob()`で復元したFFLStoreDataと、CFL_DBから本ツールで
抽出したFFLStoreDataが**96バイト全て(チェックサム含め)完全に一致**する
ことを確認済み——CFL_DBの92バイトの直後に付く2バイトの予約領域は`0x0000`
固定で問題ないことも、この一致によって実証された。

### 参考: 有志のMii編集ツール

- [`KestronProgramming/MiiJS`](https://github.com/KestronProgramming/MiiJS)
  (`infinimii.com`を支えるJSライブラリ) — Wii/DS/3DS/WiiU/Switch/Miitomo
  等ほぼ全世代のMiiフォーマットの読み書き・変換・QRコード生成に対応。
  `miiCrypto.js`が本節のAES-CCM暗号化/復号の参照実装
- [`kazuki-4ys/MiiInfoEditorCTR`](https://kazuki-4ys.github.io/web_apps/MiiInfoEditorCTR/)
  — QRコードだけでなく、名前・体型・性別・誕生日・顔パーツ等
  **FFLStoreDataそのものをフォームから直接編集**できるWebアプリ。
  MiiJSのCCM実装の一次ソース

## 10. 必要な秘密情報・鍵一覧

| 鍵/情報 | 値・取得元 | コンソール固有? | 保管場所 |
|---|---|---|---|
| keyslot 0x2E KeyX/KeyY | GodMode9でダンプ | KeyXは全機体共通、KeyYはNATIVE_FIRM由来(実質固定) | `STREETPASS_KEYSLOT_2E_FILE`(secrets) |
| `HMAC_KEY_RETAIL_CANDIDATE` | `Fsd33nrQdg0na29l\0` | いいえ(全世界共通) | `crypto.py`に直書き |
| TMP Box HMAC鍵 | `15cqj40dsrtde8m0fs0cr0x2hzafbfkl` | いいえ(Mii Plazaタイトル共通) | `mii_plaza_editor.py`に直書き |
| Mii QR AES鍵 | `59FC817E6446EA6190347B20E9BDCE52` | いいえ(全世界共通) | `mii_qr.py`に直書き |
| フレンドコード | 実機固有 | はい | `STREETPASS_FRIEND_CODE_FILE`(secrets) |

### keyslot 0x2E のKeyX/KeyYの取得方法(`aes_keys.txt`)

GodMode9([`d0k3/GodMode9`](https://github.com/d0k3/GodMode9))を使って、**自分の3DS実機から
`aes_keys.txt`を取得する**。取得したファイルの中の`slot0x2EKeyX`と`slot0x2EKeyY`の2行が
必要な値(各16バイト=32桁の16進文字列)。

- `aes_keys.txt`は、GodMode9用のコミュニティ製スクリプト(`DumpAESkey.gm9`等)で生成する
  のが一般的で、実機のSDカードの`gm9/out/`に出力される。入手方法・実行方法は
  「GodMode9 aes_keys.txt」などで検索すれば公開情報が多数見つかる
- 生成されるファイルには複数のスロットの鍵が含まれる。このプロジェクトが使うのは
  `slot0x2EKeyX`/`slot0x2EKeyY`の2行だけ
- 値は`3DS-StreetPassEmu`の外(`secrets/`など)に、
  `{"key_x": "<32桁hex>", "key_y": "<32桁hex>"}`形式のJSONとして置き、
  環境変数`STREETPASS_KEYSLOT_2E_FILE`でそのパスを指す
  ([SETUP.md](SETUP.md) §4.2)。**リポジトリには絶対にコミットしない**
- NANDの復号に必要な`boot9.bin`・`otp.bin`と生NANDバックアップも、同じくGodMode9の
  バックアップ機能で取得する([SETUP.md](SETUP.md) §4.1)

セットアップ手順・環境変数の詳細は [SETUP.md](SETUP.md) を参照。

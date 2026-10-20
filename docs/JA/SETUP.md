# セットアップガイド(クローン直後〜動作確認まで)

このリポジトリをcloneした直後の状態から、実機3DSとのライブテストが
できるようになるまでの手順。技術的な背景は
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) を参照。

## 0. 必要なもの(機能別)

### ハードウェア

- **偽装MAC対応のUSB Wi-Fiアダプタ(必須。内蔵Wi-Fiは不可)**:
  「モニターモード対応」だけでは足りず、**任意のMACアドレス宛のフレームにハードウェアが
  ACKを返せるチップ**(wifit3の`FakeMacSupport.SPOOFABLE`)が必要です。新しく買う場合は
  **購入前にwifit3のコードで確認してください**。詳しくは[HARDWARE.md](HARDWARE.md)
- **CFW(GodMode9が動く状態)の3DS実機**(自分が所有する個体)。GodMode9でAES鍵を
  取り出すために必須です

### NANDバックアップは必須か?

**機能によります。** 「実機とすれちがう」だけならNANDバックアップは不要で、GodMode9で
取った`aes_keys.txt`だけで動きます。

| やりたいこと | 必要なもの |
|---|---|
| 実機とStreetPassの会話をし、相手のメッセージ(TMP Box)を受信・保存する | `aes_keys.txt`(GodMode9で取得、§4.2)。**NANDバックアップは不要** |
| 受信したBoxを雛形に、コメント・通知文・送信者Mii等を書き換えて送る | 同上。雛形は最初に実機から受信したBoxを使う(§4.6)。そのBoxには**自分の実機のMii**が入っているので、そのMiiのまま送るだけならNANDは不要 |
| 全く別人のMii(新規訪問者)として送る | 同上(`--new-author-id --new-mii-id`、[CUSTOM.md](CUSTOM.md)) |
| **QRコード画像**を持っているMii(自分のものでも他人のものでも)を送る | `scripts/build_tmp_box.py --mii-qr 画像.png`([CUSTOM.md](CUSTOM.md))。QRデコーダ(`zbarimg`または`pyzbar`、[REQUIREMENTS.md](REQUIREMENTS.md))が必要。**NANDバックアップは不要** |
| 本体に保存されている**他のMii**(過去にすれちがった人・QRコードで取り込んだ人)を、そのQRコード画像が無い状態で抽出して送る | **NANDバックアップ**(+`boot9.bin`・`otp.bin`)が必要(§4.1・§4.3) |
| 自分のフレンドコードを開示する(任意) | 本体の画面で確認して手動で設定(§4.4)。NANDからの自動抽出は未対応 |

NANDバックアップ・`boot9.bin`・`otp.bin`は、GodMode9のバックアップ機能で同じ本体から
取得します(§4.1)。`aes_keys.txt`の取得にNANDバックアップのファイルは不要ですが、
GodMode9を実機で実行できる状態(=CFW)は必須です。

## 1. リポジトリ本体

```bash
git clone https://github.com/mar1mo-41414/3DS-StreetPassEmu.git
cd 3DS-StreetPassEmu
```

## 2. Python環境

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest   # 全テスト(ハードウェア不要)が通ることを確認
```

依存: `pycryptodome>=3.20`(必須)、`pytest>=8.0` + `pyctr>=0.7`(dev用、
NANDイメージの読み込みテスト等に使用)。用途別の必要なソフトウェア・ハードウェア
(Pillow、zbar、AzaharPlus、Xvfb等)の一覧は[REQUIREMENTS.md](REQUIREMENTS.md)にあります。

## 3. `tools/wifit3` のセットアップ

`.gitignore`対象(このリポジトリにはコミットしない)なので、別途clone:

```bash
mkdir -p tools
git clone https://github.com/derv82/wifit3 tools/wifit3
(cd tools/wifit3 && uv sync)   # or: uv venv && uv pip install -e .
```

対応チップかどうかは [HARDWARE.md](HARDWARE.md) の手順で、`tools/wifit3/src/wifit3/chips/`
配下の`FAKE_MAC`宣言を確認してください(`SPOOFABLE`のものだけが使えます)。ライセンスはGPLv2(単体で
リポジトリ外に置いてあるのはこのため。詳細は[MONITOR_MODE.md](MONITOR_MODE.md) §5)。

USBアダプタを挿した状態で

```bash
cd tools/wifit3
uv run python -c "from wifit3.device.manager import wlan_ifaces; print(wlan_ifaces())"
```

を実行し、対応インターフェースが1つ以上返ってくることを確認する(何も
返らない場合は`sudo`が必要か、チップ非対応の可能性がある)。確認後はリポジトリのルートに戻る(`cd ../..`)。

### Linuxでsudo無し(ユーザー権限のみ)で動かす

wifit3はモニターモード(root権限が必要)を使わず、対応チップセットに
直接libusb経由でアクセスすることで3DSすれちがい通信をエミュレートする
——つまり本来sudoは不要なはず。sudoが必要に見えるのは、単にUSBデバイス
ノードのパーミッションがroot専用のままになっているだけのことが多い。

[`docs/99-wifit3.rules`](../99-wifit3.rules)(wifit3が対応する全チップセット
のVID:PIDに`plugdev`グループのアクセス権を与えるudevルール、
`tools/wifit3/src/wifit3/chips/`から抽出して作成)を使えば
解決する:

```bash
sudo cp docs/99-wifit3.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
# 自分のユーザーがplugdevグループに入っているか確認、入っていなければ:
#   sudo usermod -aG plugdev $USER   (要ログインし直し)
groups
```

適用後、USBアダプタを挿し直して(またはudevadm triggerで再認識させて)
`sudo`を付けずに§3の確認コマンド・`live_streetpass_test.py`/
`streetpass_loop.py`を実行できることを確認する。

macOS(Apple Silicon、RTL8821AU系で確認済み)は
libusbのユーザー空間アクセスに追加設定が不要で、この手順自体が
不要——`uv run --python 3.12 --with pycryptodome python ...`
(Python 3.14だと`libusb-package`のwheelが無く失敗するため3.12指定)
でそのまま動く。

## 4. 実機から材料を取り出す

このリポジトリと**同じ階層**(`3DS-StreetPassEmu`の隣)に、git管理外の
`secrets/` ディレクトリを作る。実機固有の鍵・個人情報を
ここに置き、**絶対にコミットしない**(公開鍵/共通鍵はソースコードに直書き
してあるので、ここに置くのはコンソール固有の情報だけでよい)。

```bash
mkdir -p ../secrets
chmod 700 ../secrets
```

以降のコマンドは、特に断りがなければ**このリポジトリのルート**で実行する
(`../secrets/`が秘密情報の置き場)。

| 節 | 内容 | 必要な人 |
|---|---|---|
| §4.2 | keyslot 0x2Eの鍵(`aes_keys.txt`から) | **全員(必須)** |
| §4.1・§4.3 | CTRNANDの復号、本体に保存されている他のMiiの抽出 | 他のMii(過去にすれちがった人等)を送りたく、かつそのQRコード画像が無い人だけ。NANDバックアップが必要 |
| §4.4・§4.5 | フレンドコード、最近遊んだソフト | 任意 |
| §4.6・§4.7 | 雛形Boxの取得と、送信データの組み立て | **全員(必須)** |

材料は、**CFWが入った自分の3DS実機でGodMode9([`d0k3/GodMode9`](https://github.com/d0k3/GodMode9))
を使って取得**します(`aes_keys.txt`、および§4.1・§4.3が必要な場合は`SysNAND (full)`の
バックアップ・`boot9.bin`・`otp.bin`。いずれもSDカードの`gm9/out/`に出力されます)。

### 4.1 CTRNANDの復号(NANDバックアップがある場合のみ)

`scripts/decrypt_ctrnand.py`で、生のNANDバックアップから
CTRNANDパーティションだけを復号した、そのままloop-mountできるFAT16
イメージを作る:

```bash
python scripts/decrypt_ctrnand.py \
    <serial>_sysnand_00.bin <serial>_boot9_00.bin <serial>_otp_00.bin \
    ../secrets/ctrnand_decrypted.img

mkdir -p ../secrets/ctrnand_mnt
sudo mount -o loop,ro ../secrets/ctrnand_decrypted.img ../secrets/ctrnand_mnt/
ls ../secrets/ctrnand_mnt/data/   # 32桁のid0ディレクトリが1つ見えるはず
```

(内部的には`pyctr.type.nand.NAND`の`ctr_partitions`インデックス0。
検証済み: 実際にGodMode9ダンプから復号したイメージとバイト単位で一致
することを確認済み)。以降の§4.3はこのマウント先から読む。
使い終わったら`sudo umount ../secrets/ctrnand_mnt/`を忘れずに。

### 4.2 keyslot 0x2E の鍵(`STREETPASS_KEYSLOT_2E_FILE`)

GodMode9で取得した`aes_keys.txt`(実機のSDカードの`gm9/out/`に出力される。
生成方法は「GodMode9 aes_keys.txt」で検索すれば公開情報が多数ある。
詳細は[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §10)の
`slot0x2EKeyX`/`slot0x2EKeyY`の行を使い、以下の形式のJSONを作る:

```json
{
  "key_x": "00112233445566778899aabbccddeeff",
  "key_y": "00112233445566778899aabbccddeeff"
}
```

(各16バイト=32桁の16進文字列。上記は例で実際の値ではない)

```bash
export STREETPASS_KEYSLOT_2E_FILE=$(realpath ../secrets)/streetpass_keyslot_2e.json
```

代替手段: 実機ホームブリュー(`homebrew/aes_oracle`、TCP port 17491)を
使い、生のKeyX/KeyYをPCに一切持ち込まずにCCMP鍵を導出することもできる
(`src/streetpass_emu/oracle.py`の`AesOracleClient`)。この場合上記の
JSONファイルは不要。

### 4.3 送信者Mii候補の抽出(自分のプロフィールMii/過去に会った相手のMii)

`scripts/extract_console_miis.py`で、§4.1でマウントしたCTRNAND内の
共有Miiデータベース(CFL_DB、Mii Maker/StreetPass Mii Plaza共通)から、
実機に登録されている全Miiを列挙・抽出できる
(構造は[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §9の「CFL_DB.datの構造」参照)。ここには
**自分のプロフィールMii**と、**過去にすれちがった相手やQRコードから
取り込んだ他人のMii**の両方が入っている(3DSのフレンドリストが管理する
「フレンド」のMiiとは別物。フレンドの一覧・フレンドコード自体は
[STATUS.md](STATUS.md)参照、現状は自動抽出できておらず本体の
画面で確認して§4.4に手動転記する):

```bash
ID0=$(ls ../secrets/ctrnand_mnt/data)
python scripts/extract_extdata_file.py \
    ../secrets/ctrnand_mnt/data/$ID0/extdata/00048000/f000000b/00000000/00000005 \
    ../secrets/cfl_db.dat

python scripts/extract_console_miis.py list ../secrets/cfl_db.dat
# [0] offset=0x8 name='(あなたのMiiのニックネーム)' ... のように一覧が出る

python scripts/extract_console_miis.py extract ../secrets/cfl_db.dat 0 ../secrets/my_mii.bin
```

`my_mii.bin`(96バイトのFFLStoreData)が、§4.7で送信者Miiとして
差し替えるファイルになる。

### 4.4 フレンドコード(`STREETPASS_FRIEND_CODE_FILE`、任意)

NANDバックアップからの自動抽出は未解決(`LocalFriendCodeSeed_B`・
frdモジュールのSystem Save Data`00020202`のいずれも生バイト検索では
principal IDを見つけられなかった)。実機の
「本体設定」→「ユーザー情報」画面等で表示される12桁のフレンドコードを
**手動で1回確認して**転記する:

```json
{"friend_code": "4126-2228-0312"}
```

無くても動く(その場合フレンド判定には正直に「フレンドではない」ことを
示す`0`を返す設計)。実機の本物のフレンドコードは個人特定性が高いため、
テスト用の別コンソール(壊れた個体等)のものを使うことを推奨する。

### 4.5 最近遊んだソフトのリスト(`STREETPASS_RECENTLY_PLAYED_FILE`、任意)

送信側のカスタマイズ用(`src/streetpass_emu/recently_played.py`参照)。
未設定でも動作に支障はない。

### 4.6 TMP Box bodyのベースファイル(雛形)

現状、TMP Box(すれちがいメッセージ)は完全にゼロから組み立てる機能は無く、
**必ず一度は実機からの本物のキャプチャを雛形にする**必要がある(ヘッダ・アイコン・
国名テーブル等、Mii/コメント以外の全域を正しく埋めるため)。

§6の①の手順で、まず何も手を加えずに`live_streetpass_test.py`を実行し、自分の実機3DSが
送ってくる**本物の送信データ**を1回受信する(`tmp_box_<mac>_<i>.bin`として保存される)。
これを`secrets/outbound/`などに保存しておけば、以降は繰り返し雛形として使える。
個人のMii・コメント文を含む実データなので、リポジトリには含めない。

### 4.7 送信データを組み立てる

雛形を書き換えて送信用のBoxを作る。`--new-ids`でヘッダID類を再生成し、実機側の
重複排除に引っかからないようにする:

```bash
mkdir -p ../secrets/outbound

# (a) NANDバックアップなし: 雛形のまま(=自分のMii)で、コメントだけ変える例
python scripts/mii_plaza_editor.py edit \
    ../secrets/outbound/tmp_box_<mac>_0.bin ../secrets/outbound/my_send_box.bin \
    --new-ids --comment "やあ、げんき?"

# (b) NANDバックアップあり: §4.3で抽出した他のMiiを送信者にする例
python scripts/mii_plaza_editor.py edit \
    ../secrets/outbound/tmp_box_<mac>_0.bin ../secrets/outbound/my_send_box.bin \
    --set-mii-file ../secrets/my_mii.bin --new-ids

# 送信前に必ず検証
python scripts/mii_plaza_editor.py verify ../secrets/outbound/my_send_box.bin
# outer HMAC / Mii CRC16 / Mii CCM tag が全て OK になっていることを確認
```

この`my_send_box.bin`が§6の②でそのまま`--outbound-tmp-box-body-template`に渡せる。
指定できる項目は[CUSTOM.md](CUSTOM.md)を参照。

## 5. 動作確認(オフライン)

```bash
pytest   # 単体テスト(ハードウェア・実機データ不要)

# TMP Box bodyファイルの中身を見る(§4.7で得たファイルがあれば)
python scripts/mii_plaza_editor.py show \
    ../secrets/outbound/my_send_box.bin
```

`outer HMAC valid: True` / `mii checksum ok: True` が表示されれば、
実装とキャプチャの整合性が取れている。

## 6. 実機ライブテスト

```bash
export STREETPASS_KEYSLOT_2E_FILE=/path/to/streetpass_keyslot_2e.json
export STREETPASS_FRIEND_CODE_FILE=/path/to/friend_code.json  # 任意

cd tools/wifit3
```

USB経由でのモニターモード操作には通常`sudo`が必要(`wifit3`がUSBデバイスを
直接掴むため)。3DS本体は**スリープ状態(すれちがい通信待ち受け中)**にして
おく。

**① まず何もカスタマイズせず1回受信する(テンプレート取得)**:

```bash
sudo -E uv run --with pycryptodome python ../../scripts/live_streetpass_test.py \
    --channel 1 --seconds 60
```

`completed_tmp_boxes`(実行ログに出力パスが表示される)に、自分の実機
3DS自身が送ってきた本物のTMP Boxが保存される。これを
`secrets/outbound/`にコピーし、§4.7の手順で`my_send_box.bin`を作る。

**② カスタマイズしたBoxを繰り返し送信する**:

```bash
sudo -E uv run --with pycryptodome python ../../scripts/streetpass_loop.py \
    --channel 1 --cycle-seconds 120 \
    --outbound-tmp-box-body-template ../../../secrets/outbound/my_send_box.bin \
    --out-dir received_boxes/
```

(`--fresh-each-cycle`はヘッダIDに加えて送信者Miiの`mii_id`まで毎回
再生成してしまう——§4.7で意図的に選んだMiiの識別情報を維持したい場合は
**付けないこと**。複数の相手に同じBoxを送っても実機側の重複排除
(`messageId`ベース)で自然に弾かれるだけで実害はない)

送信者Mii・コメント・通知文言等、`mii_plaza_editor.py edit`で変更できる
項目の詳細は [CUSTOM.md](CUSTOM.md) にまとめてある。

### チャンネルについて

3DSのStreetPassは特定のチャンネル固定ではない可能性があるため、
`--channel`を変えて試す価値がある(このプロジェクトではチャンネル1で
安定して成立することを確認済み)。

## 7. トラブルシューティング

症状別の切り分けは **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** にまとめてある。
よくあるもの:

- 実機のフレームは届くのに会話が進まない → `STREETPASS_KEYSLOT_2E_FILE`が`sudo`経由で
  引き継がれていない(TROUBLESHOOTING.md A-2)
- 緑ランプは点灯するのにMii広場に相手が出ない → `mii_plaza_editor.py verify`で
  3項目(HMAC / CRC16 / CCMタグ)が全て`OK`か確認(同 C-1)

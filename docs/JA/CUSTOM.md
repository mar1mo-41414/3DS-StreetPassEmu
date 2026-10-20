# 送信データのカスタマイズ(`mii_plaza_editor.py`)

[SETUP.md](SETUP.md) §6の②で送信するBoxは、`scripts/mii_plaza_editor.py
edit`で自由に書き換えられる。このファイルはその`edit`サブコマンドの
各オプションを、実用目的別に整理したリファレンス。フィールド構造は[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md)を参照。

```bash
python scripts/mii_plaza_editor.py edit <入力.bin> <出力.bin> [オプション...]
python scripts/mii_plaza_editor.py verify <出力.bin>   # 送信前に必ず確認
```

`verify`で`outer HMAC`/`Mii CRC16`/`Mii CCM tag`の3つ全てが`OK`になって
いることを確認してから送信すること。どれか1つでも`NG`だと実機に無言で
拒否される。

## 雛形なしでゼロから作る

雛形にできる本物のBoxが手元に無いときは、`scripts/build_tmp_box.py`で生成できます:

```bash
python scripts/build_tmp_box.py --mii my_mii.bin --comment "こんにちは" -o box.bin
# または、Mii QRコードの画像から送信者Miiを取る(zbarimgまたはpyzbarが必要):
python scripts/build_tmp_box.py --mii-qr my_mii_qr.png --comment "こんにちは" -o box.bin
# 任意: --smdh app.smdh | --title 名前 | --large-icon img.png --small-icon img.png \
#       --header-icon img.png | --prefecture 福岡県 | --hobby 10 | --counter N
```

`--mii`は生の96バイトFFLStoreData、または112バイトの暗号化Mii blob/MiiQRペイロード。`--mii-qr`は
Mii作成の「Miiを送る」が本体内のどのMiiからでも作れるQRコードの画像を読む(CCMタグとCRC16を検証するので、壊れた/Mii以外のQRは拒否される)。
本物のQRコード由来のMiiは本物のauthor_id/mii_idを持つので、乱数生成したIDが拒否される問題を避けられる。ヘッダ・
TLV・本文・HMACトレーラーを生成し、Mii Plazaが必要とする部分だけを埋めます
([PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md)参照)。それ以外はゼロです。画像はアイコンの
サイズに縮小されます(Pillowが必要)。出来たBoxは[EMULATOR_TEST.md](EMULATOR_TEST.md)で実機なしに
確認でき、`mii_plaza_editor.py edit`もそのまま適用できます。コードからは
`streetpass_emu.tmp_box_builder.BoxSpec` / `build_message`。`--random-mii [--nickname 名前]`は、QRコードが無いときに、見た目も author_id / mii_id もランダムな新しいMiiを作ります。
`--new-ids`は任意のMiiに新しいIDを付けます。どちらも、Mii広場では新しい訪問者として扱われます。
`--prefecture`(日本語名・英語名・JIS番号)で国・地域のコードと名前が入ります。指定しないと居住地は「_」と表示されます。
`--hobby N`は「ぼく…が趣味なんだ」の一文を選びます(0=なし、判明しているのは 1=イラスト、9=インターネット、10=ゲーム)。
アイコン未指定のときは灰色の代替アイコンが入ります(ゼロのままだと黒い四角になります)。
**この方法で作ったBoxは、実機のMii広場で受理されることを確認しました(LinuxとmacOSのホストから)。**

## 毎回付けるべきオプション

### `--new-ids`

`messageId`/`messageId2`/`batchId`/`senderId`/`senderId2`/`created`を
ランダム化する。**同じBoxを再送する場合は必ず付けること**——`messageId`が
同じままだと実機側が「既に受信済み」として重複排除し、何も起こらない
([PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §7の`messageId`の項)。識別情報(author_id/
mii_id)には影響しないので、`--set-mii-file`等と組み合わせても「誰として
認識されるか」は変わらない。

## 送信者Mii(誰として認識されるか)を変える

### `--set-mii-file <96バイトのFFLStoreDataファイル>`

送信者Miiを丸ごと差し替える。[SETUP.md](SETUP.md) §4.3の
`scripts/extract_console_miis.py extract`で自分のCFL_DBから抽出した
ファイルをそのまま渡せる——**顔・ニックネーム・作成者・識別情報
(author_id/mii_id)を含む全てが差し替わる**。実機は「その`mii_id`を
これまでに見たことがあるか」で判定するため:

- CFL_DBに既にある(=実機が既に知っている)Miiを渡す → 「n回目だね!」
  (再会)として受理される
- 実機が一度も見たことのない新しいauthor_id/mii_id(後述の
  `--new-author-id`/`--new-mii-id`/`--set-identity`で作る)を渡す →
  「初めまして!」(新規訪問者)として受理される

### `--new-author-id` / `--new-mii-id`

送信者Miiの顔・ニックネームは維持したまま、識別情報の片方または両方だけを
新規ランダム値に差し替える(`--new-mii-id`は3DSの生成規則である「先頭
バイトの上位nibble=`0x9`固定」を自動的に満たす値を生成する)。両方指定
すれば完全に別人の識別情報になり、「初めまして!」の新規訪問者として
登録される(実機で確認済み)。

### `--set-identity <author_id 16進8バイト> <mii_id 16進10バイト>`

乱数ではなく、指定した具体的な値に差し替える。他機の本物の識別情報を
そのまま使う実験等に使う。

### `--set-mole 0|1`

顔パーツの「ほくろ」の有効/無効だけを切り替え、CRC16を再計算する。
author_id/mii_id/ニックネームは一切変えない——「識別情報は同じままで
Mii内容だけ変える」という切り分け実験用のオプション。

## メッセージ本文を変える

### `--comment "文字列"`

自己紹介コメント欄を書き換える。**16文字まで**(実機Mii Plazaの入力欄
自体の上限)。元のコメントが何文字であっても16文字まで自由に伸縮できる。

### `--notification-message "文字列"`

すれちがい広場の通知(「誰か来ています!」相当)の文言を書き換える。
`--comment`とは別のフィールド(ヘッダのTLV拡張領域)。
元の文字列と同じ文字数以下である必要がある。

### `--body-header-title <TITLE_ID> <TITLE_VERSION> <NAME>`

body先頭の「送信者の本体を最後に設定/更新したタイトル」情報を書き換える
(例: `0x0004001000020800 0x0001 "Mii広場"`)。表示上の見た目には影響
しない調査用フィールド。

## 調査・デバッグ用(通常は使わなくてよい)

### `--fuzz-unexplored-fields`

`titleId2`/`unknown_1`/`messageVersion`/`flags`/`sendMethod`/`unopened`/
`newFlag`/`sendCount`/`forwardCount`/`userData`を一括でランダム化する。
実機は問題なく受理することを確認済み。
「これらのフィールドが受理判定に関係ないこと」を再確認したい場合のみ使う。

### `--comment-length-field <値>`

コメント欄先頭の正体不明なu32フィールド単体を書き換える(可視文字列は
変えない)。正体は未解明のまま実害が出るまで調査を保留しているフィールドで、通常のカスタマイズでは触る必要はない。

## 組み合わせ例

```bash
# 自分のプロフィールMiiのまま、コメントだけ変えて再送
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --comment "やあ、げんき?"

# CFL_DBから抽出した別のMii(例: 過去に会った他人のMii)として、コメント付きで送信
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --set-mii-file other_mii.bin --comment "また会えたね"

# 完全な別人(新規訪問者)として送信
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --new-author-id --new-mii-id
```

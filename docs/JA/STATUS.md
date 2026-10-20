# 現状まとめ: できること / まだできないこと / 未解決の課題

このプロジェクトの到達点を、再現手順つきで整理したもの。プロトコルの確定仕様は
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md)、セットアップは[SETUP.md](SETUP.md)、
送信データのカスタマイズは[CUSTOM.md](CUSTOM.md)、Mii Plaza以外のゲームの
メッセージ形式は[GAME_FORMATS.md](GAME_FORMATS.md)を参照。

## 前提: このプロジェクトは何をするものか

**手持ちの3DS実機に対して、PCを「仮想のすれちがい相手」として接続する研究用ツール**です。
3DS本体のエミュレータでも、オンライン中継(StreetPassリレー)でもありません。
実機の電波の届く範囲で、USB Wi-Fiアダプタ越しに実機と直接会話します。

## 動作確認の環境

- 3DS: 日本版の旧型Nintendo 3DS、StreetPass Mii Plaza(アップデート版)
- OS: Linux x86_64、Raspberry Pi 5(Linux)、macOS(Apple Silicon)
- USB Wi-Fiアダプタ: 偽装MAC対応のチップが必須。確認済み機種と、買う前の確認方法は
  [HARDWARE.md](HARDWARE.md)
- `pytest`はハードウェア不要で全件通る
- **未検証**: 他リージョンの本体、New 3DS系、Windows、上記以外のアダプタ
- 機能ごとに必要なもの(Miiを送るのにNANDバックアップは要らない: Mii作成の「Miiを送る」のQRコードで足りる。NANDはまとめて抽出したいときの任意の手段)は
  [SETUP.md](SETUP.md) §0の表を参照

## 1. できること(再現方法つき)

| # | できること | 再現方法 |
|---|---|---|
| 1 | 実機3DS(スリープ中)とStreetPassの会話を成立させ、TMP Box(すれちがいメッセージ本体、約32KB)を双方向にやり取りする | [SETUP.md](SETUP.md) §3(Wi-Fiドライバ)、§4.2(鍵)、§6 → `scripts/live_streetpass_test.py` |
| 2 | 相手が送ってきたTMP Boxを保存し、内容(コメント、送信者Mii、各種ID)の表示とHMAC/CRC16/CCMタグの整合性検証をする | `scripts/mii_plaza_editor.py show <box>` / `verify <box>` |
| 3 | 送信するTMP Boxの書き換え: あいさつコメント(16文字まで)、通知文言、ヘッダID類、送信者Mii(顔・ニックネーム・識別情報を丸ごと) | [CUSTOM.md](CUSTOM.md) → `scripts/mii_plaza_editor.py edit` |
| 4 | 書き換えたBoxを実機に送り、Mii広場の「すれちがい」として受理させる。既に会ったことのあるMiiは「n回目」、未知の識別情報(author_id/mii_id)は「初めまして」の新規訪問者として扱われる | [SETUP.md](SETUP.md) §4.7・§6 → `scripts/streetpass_loop.py --outbound-tmp-box-body-template <box>` |
| 5 | (NANDバックアップがある場合)NANDバックアップだけから材料を取り出す: CTRNANDの復号、共有Miiデータベース(CFL_DB)からの自分のMii/過去に会った相手のMiiの抽出 | [SETUP.md](SETUP.md) §4.1・§4.3 → `scripts/decrypt_ctrnand.py` / `extract_extdata_file.py` / `extract_console_miis.py` |
| 6 | Wi-Fi層のCCMP暗号鍵の導出をPC単体・オフラインで行う(実機への問い合わせ不要)。実機のAESキースロット0x2Eの鍵材料を、自分の実機のGodMode9ダンプから用意する前提 | [SETUP.md](SETUP.md) §4.2、[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §3 |
| 7 | 実機のホームブリュー経由の代替経路: キースロット0x2Eをオラクルとして使う(`homebrew/aes_oracle`)、CECDのSPR経路でメッセージを注入する(`homebrew/spr_inject`) | `homebrew/aes_oracle/README.md`、各ディレクトリのMakefile(devkitARM) |
| 8 | Mii Plaza以外のゲーム(とびだせ どうぶつの森)のStreetPassメッセージ本文の構造を、静的解析で読み解く(**実機での検証はまだ**) | [GAME_FORMATS.md](GAME_FORMATS.md) |
| 9 | **TMP Boxをゼロから生成する**(実機から受信したBoxを雛形にしない): ヘッダ・TLV・本文・HMACを組み立てる。アイコン画像/SMDHの取り込み付き(**実機での検証はまだ、エミュレータでは受理を確認**) | [CUSTOM.md](CUSTOM.md) → `scripts/build_tmp_box.py` |
| 10 | 実機なしで、BoxをエミュレータのMii Plazaに通して**受理されるか**を確認する。Boxの各領域が受理に必要かの切り分けにも使える | [EMULATOR_TEST.md](EMULATOR_TEST.md) → `scripts/emu_receiver_test.py` / `emu_bisect_box.py` |
| 11 | 編集・生成の全てを、どのOSでもブラウザの**GUI**(送受信・Mii・Box編集・識別情報・ファイル・ログのタブ)から行う。送受信ループの開始/停止もここから | [GUI.md](GUI.md) → `python scripts/gui.py`(編集系は動作確認済み。開始/停止は開発者の環境でのみ確認) |

### 受理される送信データの条件(Mii Plaza)

実機が送信者Miiを受理するための条件は、書き換えた後に次の3つが全て正しいこと
(`mii_plaza_editor.py verify`で確認できる):

1. TMP Box末尾のHMAC-SHA256(body部分に対して計算)
2. 送信者MiiのCRC16(FFLStoreData内)
3. 送信者Mii blobの**AES-CCM認証タグ(16バイト全体)**

3つ目を欠くと、実機は何のエラーも出さずに黙ってそのMiiを破棄する(緑ランプは
点灯するがMii広場には出ない)。調査で最も時間を要した落とし穴で、詳細は
[GAME_FORMATS.md](GAME_FORMATS.md)の「Mii Plazaの受理判定」を参照。

## 2. まだできないこと

- **Mii Plaza以外のゲームのメッセージを実機に送る**: とびだせ どうぶつの森の
  メッセージ形式は静的解析で分かっているが、実機で受信データを採取しての裏付け、
  およびこのプロジェクトの送信経路への組み込み(別のタイトルIDのサービスとして
  提示する処理)は未実装。
- **ゼロから作ったBoxを実機に送って確認する**: ビルダー(`build_tmp_box.py`)はあり、
  エミュレータ上のMii Plazaでは受理されるが、実機での確認は未実施。ビルダーが埋めない
  領域(コンソール固有の記録・統計)は全てゼロで、訪問者の表示が簡素になる可能性がある。
  また送信者Miiは既存の96バイトFFLStoreDataが必要で、Miiの新規合成機能は無い。
- **自分のフレンドコードをNANDバックアップから自動抽出する**: フレンドリスト機能の
  セーブデータは3DS独自のセーブデータファイルシステムを内蔵しており、未解析。
  本体の画面で確認して手動で設定する運用(StreetPassの成立自体には必須ではない)。
- **フレンドリストに登録された友達のMiiの抽出**: 同上。なお「過去にすれちがった人・
  Mii QRコードから取り込んだ人」のMiiはCFL_DBから取れる(上表#5)。
- **自己紹介コメントを16文字より長くする**: 実機の入力欄の上限に合わせた仕様。
- **2台の実機を同時に用いた電波上の第三者検証**(Wireshark等での双方向キャプチャ)。
- **StreetPass中継サーバー(リレー)・SpotPass**: 対象外。

## 3. 未解決の課題

優先度は「実害が出たら調べる」ものと「次に取り組む価値があるもの」で分けている。

### 次に取り組む価値があるもの

| 課題 | 概要 |
|---|---|
| ゲーム固有メッセージの実機検証 | とびだせ どうぶつの森のメッセージ(`userData=1`: 家+プレイヤー、`userData=2`: 引っ越し住民)の表を、実機から本物を採取して裏付ける。未特定の8バイトフィールドが2箇所、プレイヤーデータ(0x6B88バイト)の内訳も未解読 |
| ゲーム固有メッセージの送信経路への統合 | 別タイトルIDのサービスとして提示し、本文のCRC-32Cを再計算して送る方法の設計。HMAC付き書き込み経路を使うかは未確認 |
| 他のStreetPass対応ゲームの解析 | マリオカート7(ゴースト)、ファイアーエムブレムif等。ゲームごとにMii Plazaと同程度の解析作業が必要 |
| タイミング制約の有無 | ハンドシェイクが途中で止まることがあるが、Wi-Fi環境の問題か応答タイミング制約によるものか切り分けていない |

### 実害が出るまで調べない(優先度低)

| 課題 | 概要 |
|---|---|
| コメント欄先頭のu32とその後ろの小さなバイト | 先頭u32は上限付きの単調増加カウンタと判明。続くバイト(`+0x06`〜`+0x09`)は表情・吹き出し等の列挙値の可能性があるが未確認。コメントの読み書きはNUL終端判定で足りている |
| `IdentityPacket`の未解明部分 | `timestamp`の先頭4バイト(年月日)以外の8バイトの意味が不明 |
| consoleID/MACアドレスの生成規則 | 値の生成規則が不明。乱数で代替しているが、実機との通信で問題は出ていない |
| TMP Box body先頭の領域 | 先頭のタイトルID・バージョン・表示名の3点セット(送信者が最後にMiiを設定したタイトル)は判明。+0x10の定数2つ(`1`、`0x80`)の意味は不明。表示名はSMDHタイトル表の先頭エントリ |
| TMP Box body末尾の統計領域 | 送信元コンソールのローカルな使用統計(プレイ時間・回数)のスナップショットらしいが、各値の対応は未解読。受理判定とは無関係 |
| `CecMessageHeader`の各種フラグ | 全てランダム化しても受理・表示に影響しないことは確認済み。個々の意味は未解明 |
| 「初めまして」ポップアップと詳細画面の「n回目」表示の食い違い | メッセージ単位とMii単位の別カウンタという仮説。未検証 |

# 3DS-StreetPassEmu

[English](README.md) | **日本語**

**手持ちの3DS実機に、PCを「仮想のすれちがい相手」として接続する研究用ツール。**
3DS本体のエミュレータでも、オンラインのStreetPass中継(リレー)でもありません。
USB Wi-Fiアダプタ越しに、電波の届く範囲の自分の実機と直接StreetPassの会話をします。

> **最初に確認してください**
> - 必要なのは「モニターモード対応」ではなく、**偽装MAC宛のフレームにハードウェアがACKを
>   返せるUSB Wi-Fiアダプタ**です。これを満たさないアダプタでは動きません。
>   新しく買う場合は**購入前にwifit3のコードで確認**してください → [docs/JA/HARDWARE.md](docs/JA/HARDWARE.md)
> - 自分が所有するCFW入りの3DS実機が必要です(GodMode9でAES鍵を取り出すため)。
> - NANDバックアップが要るのは「本体に保存された他のMiiを抽出して送る」場合だけです。
>   機能別の要否は下の表を参照。

## できること

- 実機3DS(スリープ中)とStreetPassの会話を成立させ、すれちがいメッセージ(TMP Box)を
  双方向にやり取りする
- 受信したメッセージの内容表示と、整合性(HMAC/CRC16/CCMタグ)の検証
- 送信メッセージの書き換え: あいさつコメント、通知文言、送信者Mii(顔・ニックネーム・
  識別情報を丸ごと)。実機のMii広場に「初めまして」/「n回目」として表示される
- 実機のNANDバックアップから、本体に保存された他のMii(過去に会った人等)を取り出す
- メッセージを雛形なしでゼロから生成する。また、エミュレータ上のMii PlazaにBoxを通して、受理されるか
  を実機なしで確認する(ゼロから作ったBoxの実機での確認は未実施)
- Mii Plaza以外のゲーム(とびだせ どうぶつの森)のメッセージ形式の解析結果
  (静的解析のみ。実機での検証・送信は未実装)

できること・まだできないこと・未解決の課題の詳細と再現手順は
**[docs/JA/STATUS.md](docs/JA/STATUS.md)** を参照。

## 機能別に必要なもの

| やりたいこと | 必要なもの |
|---|---|
| 実機とすれちがい、メッセージを受信・保存する | CFW入りの3DS(GodMode9で取った`aes_keys.txt`)、偽装MAC対応のUSB Wi-Fiアダプタ。**NANDバックアップは不要** |
| 受信したBoxを雛形に、コメント・通知文・別人Mii等を書き換えて送る | 同上 |
| Boxをゼロから作る / Mii Plazaが受理するかをエミュレータで確認する(実機不要) | 生成だけならPythonのみ。エミュレータテストには自分のMii Plazaのダンプも必要 → [docs/JA/EMULATOR_TEST.md](docs/JA/EMULATOR_TEST.md) |
| 本体に保存された他のMii(過去にすれちがった人等)を抽出して送る | 上記に加えて**NANDバックアップ**(+`boot9.bin`・`otp.bin`) |

対応環境: Linux(Raspberry Pi含む)またはmacOS、Python 3.10以上。Windowsは未検証。

## クイックスタート

```bash
git clone https://github.com/mar1mo-41414/3DS-StreetPassEmu.git
cd 3DS-StreetPassEmu
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest                      # ハードウェア不要のテスト一式
```

実機とすれちがうまでの手順(Wi-Fiドライバの用意、鍵の取り出し、最初のメッセージ受信、
書き換えて送信)は **[docs/JA/SETUP.md](docs/JA/SETUP.md)** に上から順にまとめてあります。

## ドキュメント

| ファイル | 内容 |
|---|---|
| [docs/JA/STATUS.md](docs/JA/STATUS.md) | できること(再現方法つき) / まだできないこと / 未解決の課題 |
| [docs/JA/REQUIREMENTS.md](docs/JA/REQUIREMENTS.md) | 用途別の必要なソフトウェア・ハードウェア(Pythonパッケージ、システムのツール、エミュレータ等) |
| [docs/JA/HARDWARE.md](docs/JA/HARDWARE.md) | USB Wi-Fiアダプタの選び方(偽装MAC対応の確認方法)、動作確認表 |
| [docs/JA/SETUP.md](docs/JA/SETUP.md) | clone直後から実機とすれちがうまでの手順 |
| [docs/JA/TROUBLESHOOTING.md](docs/JA/TROUBLESHOOTING.md) | うまくいかないときの症状別の切り分け |
| [docs/JA/CUSTOM.md](docs/JA/CUSTOM.md) | 送信データのカスタマイズ(`mii_plaza_editor.py`)と、ゼロからの生成(`build_tmp_box.py`) |
| [docs/JA/EMULATOR_TEST.md](docs/JA/EMULATOR_TEST.md) | 実機なしでエミュレータのMii PlazaにBoxを通して確認する |
| [docs/JA/PROTOCOL_REFERENCE.md](docs/JA/PROTOCOL_REFERENCE.md) | 確定しているプロトコル・データ形式の仕様 |
| [docs/JA/GAME_FORMATS.md](docs/JA/GAME_FORMATS.md) | Mii Plazaの受理判定、とびだせ どうぶつの森のメッセージ形式 |
| [docs/JA/MONITOR_MODE.md](docs/JA/MONITOR_MODE.md) | Wi-Fi層(モニターモード)の設計 |
| [docs/JA/ANALYSIS_ENV.md](docs/JA/ANALYSIS_ENV.md) | 動的・静的解析環境メモ(上級者向け) |

英語版は [docs/EN/](docs/EN/) にあります。

## ツール

| スクリプト | 用途 |
|---|---|
| `scripts/live_streetpass_test.py` | 実機との接続を1回試す動作確認 |
| `scripts/streetpass_loop.py` | すれちがい通信を繰り返し試行する(送信データ指定可) |
| `scripts/mii_plaza_editor.py` | TMP Boxの表示・検証・書き換え |
| `scripts/decrypt_ctrnand.py` | 生NANDバックアップからCTRNANDを復号 |
| `scripts/extract_extdata_file.py` | NAND内のextdataファイルを展開 |
| `scripts/extract_console_miis.py` | 共有MiiデータベースからMiiを列挙・抽出 |
| `scripts/extract_recently_played.py` | ダンプ内の「最近遊んだソフト」リストを探索 |

## Issueに貼らないでほしいもの

次のものは**個人情報・機体固有情報**です。Issueやディスカッション、スクリーンショット、
ログに**貼らないでください**(誤って貼った場合は編集して消してください):

- NANDバックアップ、`boot9.bin`、`otp.bin`、`movable.sed`、`SecureInfo_A`、`LocalFriendCodeSeed_B`等
- `aes_keys.txt`の中身、`STREETPASS_KEYSLOT_2E_FILE`のJSON(KeyX/KeyY)
- フレンドコード
- 受信したTMP Box(他人のMii・コメント・各種IDを含む)、Miiデータ/QRコード
- 実機のMACアドレス・console IDが分かるキャプチャ・ログ

相談するときは、エラーメッセージ、`mii_plaza_editor.py verify`の出力(項目名とOK/NG)、
使っているアダプタの型番とUSB IDなど、**機密を含まない情報**で十分です。
このリポジトリのテストやサンプルは、実機の生データではなく**合成データ**です。
PRで追加するテストデータも、実機由来の生データは避けて合成データにしてください。

## ライセンス

[MIT License](LICENSE)。自由にclone・改変・再配布してください。

## 注意

- 自分が所有する本体・ソフトのダンプのみを対象とした研究用途のプロジェクトです。
  このリポジトリには、任天堂の実行コード・コンソール固有の鍵・個人のデータは
  含まれていません。必要な鍵材料は自分の実機から自分で取り出します
  ([docs/JA/SETUP.md](docs/JA/SETUP.md) §4)。
- 任天堂とは無関係の非公式プロジェクトです。
- Wi-Fiドライバ層は別リポジトリ([derv82/wifit3](https://github.com/derv82/wifit3)、GPLv2)を
  `tools/wifit3`に別途cloneして使います(本リポジトリには含みません)。

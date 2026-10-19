# 3DS-StreetPassEmu

Nintendo 3DSの「すれちがい通信(StreetPass)」を、PC(モニターモード対応のUSB Wi-Fiアダプタ)で
エミュレートするための研究用実装。**自分が所有する3DS実機**のNANDバックアップから
必要な材料を取り出し、実機とすれちがい通信を成立させる。

> PC-based emulation of Nintendo 3DS StreetPass over a monitor-mode USB Wi-Fi adapter
> (research project; use only with consoles you own).

## できること

- 実機3DS(スリープ中)とStreetPassの会話を成立させ、すれちがいメッセージ(TMP Box)を
  双方向にやり取りする
- 受信したメッセージの内容表示と、整合性(HMAC/CRC16/CCMタグ)の検証
- 送信メッセージの書き換え: あいさつコメント、通知文言、送信者Mii(顔・ニックネーム・
  識別情報を丸ごと)。実機のMii広場に「初めまして」/「n回目」として表示される
- 実機のNANDバックアップだけから、鍵材料・自分のMii・過去に会った相手のMiiを取り出す
- Mii Plaza以外のゲーム(とびだせ どうぶつの森)のメッセージ形式の解析結果

できること・まだできないこと・未解決の課題の詳細と再現手順は
**[docs/STATUS.md](docs/STATUS.md)** を参照。

## 必要なもの

- CFW(GodMode9が使える状態)の3DS実機と、そのNANDバックアップ一式
- モニターモード相当の操作ができるUSB Wi-Fiアダプタ(RTL8812AU/RTL8821AU系などで確認)
- Linux(Raspberry Pi含む)またはmacOS、Python 3.10以上

## クイックスタート

```bash
git clone https://github.com/mar1mo-41414/3DS-StreetPassEmu.git
cd 3DS-StreetPassEmu
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest                      # ハードウェア不要のテスト一式
```

実機とすれちがうまでの手順(Wi-Fiドライバの用意、NANDバックアップからの材料抽出、
最初のメッセージ受信、書き換えて送信)は **[docs/SETUP.md](docs/SETUP.md)** に
上から順にまとめてある。

## ドキュメント

| ファイル | 内容 |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | できること(再現方法つき) / まだできないこと / 未解決の課題 |
| [docs/SETUP.md](docs/SETUP.md) | clone直後から実機とすれちがうまでの手順 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | うまくいかないときの症状別の切り分け |
| [docs/CUSTOM.md](docs/CUSTOM.md) | 送信データのカスタマイズ(`mii_plaza_editor.py`の使い方) |
| [docs/PROTOCOL_REFERENCE.md](docs/PROTOCOL_REFERENCE.md) | 確定しているプロトコル・データ形式の仕様 |
| [docs/GAME_FORMATS.md](docs/GAME_FORMATS.md) | Mii Plazaの受理判定、とびだせ どうぶつの森のメッセージ形式 |
| [docs/MONITOR_MODE.md](docs/MONITOR_MODE.md) | Wi-Fi層(モニターモード)の設計 |
| [docs/ANALYSIS_ENV.md](docs/ANALYSIS_ENV.md) | 動的・静的解析環境メモ(上級者向け) |

## ツール

| スクリプト | 用途 |
|---|---|
| `scripts/live_streetpass_test.py` | 実機との接続を1回試す動作確認 |
| `scripts/streetpass_loop.py` | すれちがい通信を繰り返し試行する(送信データ指定可) |
| `scripts/mii_plaza_editor.py` | TMP Boxの表示・検証・書き換え |
| `scripts/decrypt_ctrnand.py` | 生NANDバックアップからCTRNANDを復号 |
| `scripts/extract_extdata_file.py` | NAND内のextdata/sysdataファイルを展開 |
| `scripts/extract_console_miis.py` | 共有MiiデータベースからMiiを列挙・抽出 |
| `scripts/extract_recently_played.py` | ダンプ内の「最近遊んだソフト」リストを探索 |

## ライセンス

[MIT License](LICENSE)。自由にclone・改変・再配布してください。

## 注意

- 自分が所有する本体・ソフトのダンプのみを対象とした研究用途のプロジェクトです。
  このリポジトリには、任天堂の実行コード・コンソール固有の鍵・個人のデータは
  含まれていません。必要な鍵材料は自分の実機から自分で取り出します
  ([docs/SETUP.md](docs/SETUP.md) §4)。
- 任天堂とは無関係の非公式プロジェクトです。
- Wi-Fiドライバ層は別リポジトリ([derv82/wifit3](https://github.com/derv82/wifit3)、GPLv2)を
  `tools/wifit3`に別途cloneして使います(本リポジトリには含みません)。

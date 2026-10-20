# 必要なソフトウェア・ハードウェア

やりたいことによって必要なものが変わります。*(システム)*と書いたもの以外は、Pythonの
仮想環境の中に入ります。

## 常に必要

| 何が | 備考 |
|---|---|
| Python 3.10以上 | 3.12推奨 |
| `pycryptodome >= 3.20` | `pip install -e .`で入る |
| Linux、macOS、Windows | Windows: RTL8812AU系アダプタでコマンドラインを確認。wifit3が初回にWinUSBドライバを入れる |

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"      # テスト用にpytestとpyctr。ハードウェア不要
```

## 用途別

### GUI([GUI.md](GUI.md))
- 常に必要なパッケージとWebブラウザだけ。`python scripts/gui.py`で起動。
- 送受信タブには「実機とすれちがう」の項目が全部必要。編集系のタブは何も追加で要らない。

### 実機とすれちがう(Boxの受信・送信)
- 偽装MACにACKを返せるUSB Wi-Fiアダプタ — [HARDWARE.md](HARDWARE.md)。必須
- CFW入りの3DSと**GodMode9**。自分の実機から`aes_keys.txt`を取り出すため(他のMiiを抽出する場合
  をまとめて抽出したい場合の任意の手段として、NANDバックアップ+`boot9.bin`+`otp.bin`。個別のMiiならMii作成の「Miiを送る」のQRで足りる)
- `wifit3`(GPLv2、`tools/wifit3`に別途clone)と**uv** — [SETUP.md](SETUP.md) §3
- Linux: ユーザー権限でlibusbに触れる設定(`docs/99-wifit3.rules`のudevルール)、または`sudo`

### Boxの編集・生成
- `mii_plaza_editor.py`と、96バイトのMiiファイルからのBox生成は、常に必要なパッケージだけで動く
- **Pillow**(標準の依存になり、自動で入る): PNG/JPEG画像をアイコンにする(`--large-icon`、
  `--small-icon`、`--header-icon`)
- **Mii QRコード画像からMiiを作る**(`build_tmp_box.py --mii-qr`)には、生のバイト列を返せる
  QRデコーダが必要: `zbarimg`コマンド*(システム: Debian/Ubuntuは`zbar-tools`、macOSは
  `brew install zbar`)*、`pyzbar`(`pip install -e ".[mii-qr]"`。こちらもzbarライブラリ
  *(システム)*が必要)、または**OpenCV**(`pip install -e ".[mii-qr-opencv]"`。システムのライブラリ不要で、
  どのOSでも動く)
- `qrcode[pil]`(`pip install -e ".[tools]"`)は、Mii QR画像を**生成する**ときだけ(テスト・実験用)

### エミュレータでBoxを確認する([EMULATOR_TEST.md](EMULATOR_TEST.md))
- **AzaharPlus**(暗号化タイトルを直接起動できるフォーク)
- 自分の実機の**Mii Plazaのダンプ**: ベースタイトルの`.app`とSDのアップデートタイトル
  (GodMode9などで)
- `Xvfb`*(システム)*、ImageMagickの`import`*(システム)*。`--trace`にだけ`gdb-multiarch`*(システム)*
- ダンプの準備に使える補助: `pyctr`(devに含まれる)、復号済みCTRNANDイメージからファイルを
  取り出す`mtools`*(システム)*

### 実機側ホームブリュー(`homebrew/`)
- devkitARM + libctru。公式の`devkitpro/devkitarm`のDockerイメージを使えば、ホストにdevkitPro
  を入れずに済む

### 解析([ANALYSIS_ENV.md](ANALYSIS_ENV.md))
- Ghidra(ヘッドレスのスクリプトはJava)、`gdb-multiarch`、AzaharPlus

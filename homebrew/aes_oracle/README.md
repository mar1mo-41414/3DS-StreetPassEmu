# aes_oracle

実機の`PS:EncryptDecryptAes`(キースロット0x2E, StreetPass鍵)を直接呼び出すだけの
ホームブリュー。調査結果 の静的解析でキーバイト列そのものの発見が難航して
いるため、鍵の値を知らなくても実機に暗号処理そのものを実行してもらう「鍵オラクル」方式の
検証用ツール。

CTR値は完全にこちら側(Hash Block経由)でコントロールできるため、実際の鍵バイト列を
知る必要はない。

## 使い方

1. `aes_oracle.3dsx` をSDカードの `/3ds/` フォルダにコピー
2. Homebrew Launcher経由で起動
3. `A`ボタンでソフトウェアキーボードが開くので、32文字の16進数(16バイトのCTR値)を入力
   (例: `00112233445566778899aabbccddeeff`)
4. 画面に入力したCTR・`PS_EncryptDecryptAes`の戻り値(`rc`)・結果の16バイトが表示される
   - `rc: 0x00000000` なら成功
   - エラーコードが返る場合、キースロット0x2Eが(このホームブリューの実行コンテキストでは)
     未初期化である可能性がある(CECD自身が使う直前に遅延初期化している、という仮説の傍証になる)
5. `START`で終了

## ビルド方法

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/project -w /project \
    devkitpro/devkitarm:latest make
```

(devkitPro本体はホストにインストールせず、Docker Hub経由の公式イメージを使う。
`apt.devkitpro.org`がthe host PCのネットワークからブロックされているため)

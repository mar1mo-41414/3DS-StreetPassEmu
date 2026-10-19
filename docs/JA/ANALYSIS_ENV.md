# 動的・静的解析環境メモ(上級者向け)

SETUP.mdの範囲を超えて、未解明フィールドの調査や新しいゲームの解析を行う場合の環境メモ。

## 1. 動的解析環境(HMAC鍵の再確認・新たなフィールドの解析に使う場合)

[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §8のHMAC鍵は既に判明済みだが、今後さらに
未解明フィールドを調べる場合、同じ手法
(AzaharPlus + GDB)が使える。必要なもの:

- [`AzaharPlus/AzaharPlus`](https://github.com/AzaharPlus/AzaharPlus)
  (無印Azaharや他のフォークでは暗号化タイトルの直接起動ができない)
- `gdb-multiarch`(`set architecture arm`でAzaharPlus内蔵gdbstub
  `localhost:24689`にアタッチ)
- Mii Plazaの暗号化`.app`(実機NANDの`title/00040010/00020800/content/`
  配下、GodMode9等でエクスポート)
- 実機のCFL_DB.dat(`extdata/00048000/f000000b/00000000/00000005`、
  `scripts/extract_extdata_file.py`で展開できる。[SETUP.md](SETUP.md) §4.3参照)を
  AzaharPlusの`nand/data/.../extdata/00048000/F000000B/user/CFL_DB.dat`
  に配置すると、実機の本物のMiiがエミュ上でも使えるようになる

**【重要な制限】** AzaharPlus(Citra系全般)は、CECDの
ような**システムモジュールをLLE(実機バイナリそのまま実行)化する
仕組みをアーキテクチャ上持っていない**。設定にある`lle_applets`は
ソフトウェアキーボード等の「アプレット」専用で、システムモジュールには
適用できない。つまりファーム/OTP/SecureInfo等を投入しても、CECDの
判定ロジック自体は常にAzaharPlus独自のHLE再実装のまま——本物の
CECDロジックを調べたい場合はこのファイルの§2の実機Rosalina経由の
デバッグが必須になる。

とはいえOTP/SecureInfo_A/LocalFriendCodeSeed_B/movable.sedの投入自体は
無駄ではなく(Mii描画精度や一部ゲームの動作改善に寄与しうる)、GodMode9の
essentialバックアップから以下のように配置できる:

```bash
NAND_DIR=~/.local/share/azaharplus-emu/nand   # Linuxの場合
SYS_DIR=~/.local/share/azaharplus-emu/sysdata
ESSENTIAL=/path/to/gm9backup/essential  # frndseed.bin, otp.bin, secinfo.bin, movable.bin等

mkdir -p "$NAND_DIR/rw/sys" "$NAND_DIR/private"
cp "$ESSENTIAL/secinfo.bin"  "$NAND_DIR/rw/sys/SecureInfo_A"
cp "$ESSENTIAL/frndseed.bin" "$NAND_DIR/rw/sys/LocalFriendCodeSeed_B"
cp "$ESSENTIAL/otp.bin"      "$SYS_DIR/otp.bin"
cp "$ESSENTIAL/movable.bin"  "$NAND_DIR/private/movable.sed"
```

(パスは`AzaharPlus`のソース`src/core/hw/unique_data.cpp`の
`GetSecureInfoAPath()`等で確認済み)

## 2. 実機 + Rosalina内蔵GDBでの動的解析

AzaharPlusのHLE実装(CECD等のシステムモジュールは常にAzaharPlus独自の
再実装で動く、LLE化する仕組みはアーキテクチャ上存在しない——
`lle_applets`はソフトウェアキーボード等の「アプレット」専用で
システムモジュールには使えない)では確認できない、**実機の本物の
挙動**を直接デバッグしたい場合、Luma3DSのRosalinaメニュー内蔵の
GDBスタブが使える。CFWが入った実機3DSが必要。

### 準備

1. 実機3DSとPCを同じLANに繋ぐ(すれちがい通信のアドホックWiFiとは別に、
   通常のインフラストラクチャWiFi接続が必要)
2. 対象アプリ(例: Mii Plaza)を起動し、普通に操作できる状態にする
3. Rosalinaメニューを呼び出す(`L+Down+Select`長押しがデフォルト)
4. **Process list** → 対象プロセス(Mii Plazaは内部名`MEET`)を選択 →
   **Debug** を選ぶとその場でGDBスタブが起動し、リッスンしているポート
   番号が表示される(**固定ではなく毎回変わる**ので、その都度確認する)
5. PC側から接続:
   ```bash
   gdb-multiarch -q \
     -ex "set architecture arm" \
     -ex "set remotetimeout 30" \
     -ex "set confirm off" \
     -ex "target remote <3DSのIP>:<表示されたポート>" \
     -x breakpoints.txt
   ```

### 既知の注意点・ハマりどころ

- **Rosalinaのデバッグスタブは基本1回勝負**: 一度接続してGDB側が
  切断(detach/タイムアウト/kill問わず)すると、次にまた繋ぐには
  Rosalinaメニューで同じプロセスに対し再度「Debug」をやり直す必要が
  ある。ポート番号も変わることが多いので、再接続の都度確認すること
- **「Force-debug next application at launch」機能(デフォルトポート
  `4003`)はエントリポイント(crt0実行前、全レジスタ0、PC=0x100000)
  で完全に停止する**。ここから**明示的に`continue`を送らず`detach`
  してしまうとプロセスがクラッシュする**(data abort、実機に実害は
  無く該当プロセスが落ちるだけ)。スクリプトの最後は必ず(EOF任せの
  暗黙detachではなく)明示的な`continue`で終えること
- 既に起動済みのプロセスにProcess list経由でアタッチする分には、
  何度re-attachしてもクラッシュしない(通常のデバッグと同じ安全な
  detachができる)
- 生存確認: `ping <3DSのIP>`で3DS自体が生きているか、
  `nc -zv <IP> <port>`でポートが開いているかを先に確認すると
  切り分けが早い
- マルチスレッドプロセス(Mii Plazaは起動時に5スレッド程度)なので、
  ブレークポイントがどのスレッドで発火したかを`info threads`等で
  確認すること。レジスタ内容が期待値と食い違う場合、まずスレッド
  違いを疑う
- IPCコマンドバッファの内容を見たい場合、レジスタの生の値を当てずっぽうで
  読むのではなく、**Ghidraで対象関数を正しく逆アセンブルしてから**
  「`mrc p15,0,rX,c13,c0,3`でTLSを読み、`str rY,[rX,#0x80]!`でcmdbuf
  base(=rX自身)を確定させ、そこからのオフセットでフィールドを読む」
  という手順を辿ること。手作業のcapstoneトレースは間違いやすい
  (レジスタ`r0`をprogramIdだと誤読した例がある。実際には
  「サービスハンドル」で、programIdは`cmdbuf`内にあった)
- **静的解析でvtable経由の間接呼び出しに阻まれて呼び出し元が
  分からない場合、ブレークポイントヒット時に`bt`(backtrace)を打てば
  実行時のコールスタックがそのまま見える**。静的クロスリファレンスが
  効かない場面ではこちらが本命

### Ghidraでの静的解析(併用)

```bash
# .codeの復号・展開(pyctrが入ったPython環境で実行する)
python3 -c "
from pyctr.type.ncch import NCCHReader
from pyctr.type.exefs import decompress_code
from pyctr.crypto import CryptoEngine
ce = CryptoEngine(boot9='/path/to/boot9.bin')
r = NCCHReader('/path/to/0000001a.app', crypto=ce)  # NANDのtitle/00040010/00020800/content/配下
with r.exefs.open('.code') as f:
    raw = f.read()
dec = decompress_code(raw)  # ExeFSの.codeは圧縮されていることが多い
open('miiplaza.code', 'wb').write(dec)
"

# Ghidraプロジェクト作成(ベースアドレスはNCCH ExtendedHeaderのtext_addr、
# 通常0x00100000)
analyzeHeadless /path/to/project ProjectName \
  -import miiplaza.code -processor "ARM:LE:32:v6" \
  -loader BinaryLoader -loader-baseAddr 0x00100000 -overwrite

# 以降は GhidraScript(.java、Jythonの.pyはPyGhidra専用ビルドでないと
# 動かないので要注意)を -postScript で渡して逆アセンブル/デコンパイル
```

実機のNANDバックアップからMii Plazaの実行コードを取り出す際、
**バージョン違い(アップデート)が実際に起きていないか、複数の
バックアップ間でMD5を比較しておく**とよい(1日違いの2つのバックアップで
実際に比較し、コード自体は不変だったことを確認済み——ただし別のコンテンツ
(取扱説明書等)が追加されていたので、`content/`配下のファイル一覧だけで
「更新なし」と判断しないこと)。

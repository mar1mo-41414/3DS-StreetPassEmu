# モニターモードRX/TX層の調査 (wifit3)

`tools/wifit3/`(https://github.com/derv82/wifit3 のクローン、GPLv2)を調査した結果のまとめ。
このリポジトリ自体は本プロジェクトにコミットしない(`.gitignore`で除外、参考実装として手元に置くのみ)。

## 1. アーキテクチャの要点

wifit3は「Mini-Driver」と呼ばれる自前のUSBチップ直叩きドライバ層を持つ。

- Linuxカーネルの実ドライバ(ath9k, rtw88, mt76, rt2x00等)をPythonへ**Cから移植したもの**。
  PyUSB経由でUSBチップのレジスタ/ファームウェアに直接アクセスし、**OSのWi-Fiスタックを完全に
  迂回する**(Windows NDISだけでなく、LinuxのMonitorモード・macOSの制限too avoid)。
- そのため **Linux/macOS/Windowsで全く同じコードが動く**。README記載の通り、macOSは
  USBデバイスの許可("Allow")さえすれば追加ドライバ不要。
- 対応チップセットはAtheros AR9271、MediaTek MT76xx系、Realtek RTL88xx系、Ralink RT系など
  (README「Supported hardware」参照)。**チップセット単位の対応**であり、内蔵Wi-Fiでは動かない
  (外付けUSBアダプタが必須)。

→ 今回のプロジェクトが避けたい「OS依存のモニターモードドライバ」問題への**直接の解**になる。
Raspberry PiでもMacでも、対応チップセットのUSBアダプタを挿せば同じPythonコードで動く見込み。

## 2. 利用できるAPI (`chips/driver.py` の `Driver` ABC)

各チップ用ドライバは共通の抽象基底クラス `Driver` を実装しており、StreetPass実装はこれを
1個の「campaign」的モジュールとして利用すればよい(`campaigns/pmkid.py` 等と同じ立ち位置)。

主なメソッド:

- `register_rx_callback(cb: Callable[[Packet], None])`: 受信フレームをパース済み`Packet`として
  コールバックに渡す。StreetPassステートマシンはここでProbe Request/Action frameを監視する。
- `await inject_frame(frame_bytes: bytes) -> bool`: 生802.11フレームを1回送信(fire-and-forget)。
  チップのハードウェア再送(ACK待ち)にまかせる。
- `await inject_frame_slow_retry(frame_bytes, timeout=None, max_resends=0)`: ソフトウェアで
  ACK待ち・再送を行う版(要 `enable_rx_acks()`)。3DS側の応答待ちが必要な箇所で使えそう。
- `await set_channel(channel: int, scan: bool=False)`: チャンネル切り替え。
- `await connect(progress_cb=None)` / `await close()`: ブリングアップ/終了。

### ACK関連(要注目: §3のシーケンスの実装に直結)

- `enable_rx_acks()` / `record_ack()` / `acks_seen(mac)`: 送ったフレームに対する**相手からの
  ACKを受信ストリーム側で数える**仕組み。
- `enter_active_monitor(mac: bytes, bssid: Optional[bytes]) -> bytes` /
  `exit_active_monitor()`: チップの**ハードウェアオートACK機能**を、任意の(spoofした)MACに対して
  有効化する。`FakeMacSupport` enumで対応度合いが分かれる:
  - `NONE`: 不可
  - `FIXED_MAC`: カード自身のMACしかACKできない
  - `SPOOFABLE`: 任意の偽装MACをACKできる

  → StreetPassでは自分(PC)が「別の3DSのMACアドレス」になりすます必要がある(§4)ため、
  **`SPOOFABLE`なチップを選ぶ必要がある**。3dbrewの記録通りProbe Response/Action frameは
  ユニキャストでACKが必要になる可能性が高く、ここがハードウェア依存の分岐点になりうる。
  対応表は `docs/porting/CHIP-DOC.md` 配下の各chip docを要確認(次のステップ)。

## 3. フレームパース/構築

`dot11/packet.py`, `dot11/probe.py`, `dot11/ie.py` 等に802.11フレームのパーサがある
(Information Element単位の解析含む)。StreetPassのSSID
`Nintendo_3DS_continuous_scan_000` 検出やAction frame(category `0x7f`, OUI `00:1f:32`)の
判定はこれらを流用/参考にできる。ただしwifit3自体はWPA/WEPクラッキング用に特化しており、
StreetPassのAction frameペイロード構造(§6-3-2, 未解決)のパーサは自作が必要。

## 4. 移植元コードの性質(注意点)

READMEに明記: Mini-Driverは「コーディングエージェントがLinuxカーネルCドライバをPythonに移植した」
もので、実USBトラフィックのキャプチャをオフラインで再生しながら1命令ずつ検証するという手法で
作られている。**チップごとに独立したポートであり、ドライバ間でコードを共有しない方針**
(`chips/`配下のAGENTS.md記載: "don't re-use code from another driver")。

→ 新チップを追加するのと同程度の労力で「StreetPass用の送受信ロジック」を既存チップの
`driver.py`の上に薄く被せることは可能そうだが、**レジスタ書き込みの順序を変えると壊れる
(read-modify-writeが可換とは限らない)** など、ハードウェア直叩き特有の注意点がある
(`docs/porting/GOTCHAS.md`参照、要読み込み)。

## 5. ライセンス

wifit3自体はGPL-2.0-only。Mini-Driver部分をベースに派生実装を作る場合、**そのモジュールは
GPLv2に汚染される**点に注意(コピーレフト)。本プロジェクト全体をGPLv2にするか、
Mini-Driver層だけ別プロセス/別パッケージに分離するか、要検討。

## 6. 次のステップ

1. `docs/porting/CHIP-DOC.md` と実際に手元にあるUSBアダプタのチップセットを照合し、
   `FakeMacSupport.SPOOFABLE` なチップを選定する。
2. wifit3の`campaigns/`を参考に、`Driver`をラップした最小限のStreetPass RX/TXモジュールを
   `src/streetpass_emu/`側に(wifit3のコードをコピーせず、`tools/wifit3`を外部依存として
   参照する形で)実装する。
3. ライセンス方針(GPLv2汚染範囲)をこの作業に着手する前に確定する。

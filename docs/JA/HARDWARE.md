# USB Wi-Fiアダプタの選び方(必読)

**「モニターモード対応」のアダプタなら何でも動くわけではありません。**
このプロジェクトでは、PCが実機3DSに対して「別の3DSのMACアドレス」になりすまして
会話します。802.11ではユニキャストフレームに対し、受信側がごく短い時間(SIFS、
約10マイクロ秒)以内にACKを返す必要があり、ソフトウェアでは間に合いません。偽装した
MAC宛のフレームにもハードウェアがACKを返せるよう、アダプタ(チップ)側に次の能力が
必要です。

> **任意(偽装)のMACアドレス宛のフレームに、ハードウェアが自動でACKを返せること**
> (wifit3のコードでは `FakeMacSupport.SPOOFABLE`)

これが無いアダプタ(自分自身の本来のMACにしかACKしない、または未対応のもの)では、
Probe Requestの往復までは見えても、その先の会話が成立しません。内蔵Wi-Fiも使えません。

## 新しくアダプタを買う場合

**購入前に、必ずwifit3のコードで対象チップが`SPOOFABLE`か確認してください。**
製品の説明に「モニターモード対応」「パケットインジェクション対応」と書いてあっても、
それだけでは判断できません。

1. [derv82/wifit3](https://github.com/derv82/wifit3)をcloneする
2. `src/wifit3/chips/<チップ名>/driver.py`の`FAKE_MAC = FakeMacSupport.○○`を見る
   - `SPOOFABLE`: 対応(買ってよい)
   - `FIXED_MAC`: 自分のMACにしかACKできない(使えない)
   - `NONE`: ハードウェア的に不可(使えない)
   - `UNIMPLEMENTED`: wifit3に未移植。チップ自体は可能かもしれないが、現状は使えない
3. `src/wifit3/chips/products.py`に、製品名とチップの対応が載っている。買おうとしている
   製品がどのチップを積んでいるか、ここと実機のUSB ID(`lsusb`の`VID:PID`)で照合する
4. 同じ型番でも**リビジョンによって積んでいるチップが違う**製品がある。購入前に
   リビジョン/USB IDを確認すること

注意: 同じチップ系列でも、wifit3内で別実装に分かれている場合がある。たとえば
`rtl8812au`(`UNIMPLEMENTED`)と`rtl8812au_dkms`(`SPOOFABLE`)のように、
系列名が似ていても対応状況が違う。必ず実際に使われる実装の宣言を確認する。

### wifit3が`SPOOFABLE`と宣言しているドライバ(参考)

wifit3のコミット`45fb760d`(2026-09-07)時点での宣言。**本プロジェクトで実機検証したのは
下の「動作確認済み」の2機種だけ**で、これらは「wifit3がそう宣言している」という情報に
すぎない。

`ar9271_v2` / `mt76x0u` / `mt76x2u` / `mt7921au` / `mt7925au` / `rt2800usb` / `rt3070` /
`rt5370` / `rt5372` / `rt5572` / `rtl8188eus_dkms` / `rtl8812au_dkms` / `rtl8814au_dkms` /
`rtl8821au_dkms` / `rtl8821cu_dkms` / `rtl8822bu_dkms` / `rtl8822cu` / `rtl8922au`

`SPOOFABLE`ではないもの: `rt2500usb`(`NONE`)、`rtl8187`(`FIXED_MAC`)、
`rtl8812au`・`rtl8821au`・`rtl8188eus`・`rtl8822bu`・`rtw88_8814au`(`UNIMPLEMENTED`)。

## 動作確認済み / 未検証

| アダプタ | チップ | USB ID | 確認済みの環境 |
|---|---|---|---|
| Buffalo WI-U3-866D | RTL8812AU | `0411:025d` | Linux x86_64、macOS(Apple Silicon)、Windows(x86-64、WinUSBドライバ) |
| Buffalo WI-U2-433DM | RTL8821AU | `0411:0242` | Raspberry Pi 5(Linux)、macOS(Apple Silicon) |

上記以外のアダプタ・OSは**未検証**です。Windowsでは、wifit3が初回にアダプタのドライバをWinUSBに差し替えます([SETUP.md](SETUP.md) §3)。動作した/しなかった報告は歓迎します
(Issueに書く際の注意は[README](../../README.ja.md)の「Issueに貼らないでほしいもの」を参照)。

## 動作に必要なその他の条件

- LinuxではUSBデバイスへのアクセス権が必要です([SETUP.md](SETUP.md)の
  「Linuxでsudo無しで動かす」参照)。macOSは追加設定不要です
- 対象の3DSはスリープ状態(すれちがい待ち受け中)で、StreetPass Mii Plazaの
  すれちがいが有効になっている必要があります

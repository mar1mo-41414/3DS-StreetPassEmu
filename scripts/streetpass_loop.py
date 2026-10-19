"""実機の3DSに対して、すれちがい通信を繰り返し試行し続けるループスクリプト。

live_streetpass_test.py(1回だけ実行する動作確認用スクリプト)を土台に、
以下を追加している:

- インターフェースの起動・停止をサイクル毎に行う(USBデバイスを毎回
  解放するため、"Resource busy" エラーの再試行にも対応)
- サイクル毎に新しいセッションIdentity(MAC/consoleID等)を生成
- --outbound-tmp-box-body-template を指定すると、サイクル毎に
  mii_plaza_editor.TmpBox でヘッダID・送信者Miiのmii_idを再生成した
  「新鮮な」TMP Boxを自動で作って提示する(--fresh-each-cycle)
- 受信したTMP Boxはサイクル番号・タイムスタンプ付きで--out-dirに保存
- デフォルトは簡潔な1行ログ(--verbose で live_streetpass_test.py 相当の
  全フレーム生ログも出せる)

使い方:
    export STREETPASS_KEYSLOT_2E_FILE=/path/to/keyslot_2e.json
    export STREETPASS_FRIEND_CODE_FILE=/path/to/friend_code.json
    cd tools/wifit3
    uv run python ../../scripts/streetpass_loop.py \\
        --channel 1 --cycle-seconds 120 \\
        --outbound-tmp-box-body-template /path/to/body_real_from_test42.bin \\
        --comment "R8自由に書き換えたコメントだよ" \\
        --fresh-each-cycle \\
        --out-dir received_boxes/

Ctrl+Cで、現在のサイクルの終了を待たず即座に停止する。
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import sys
import time
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))

from streetpass_emu import dot11, spmtp  # noqa: E402
from streetpass_emu.driver_bridge import StreetPassDriverBridge  # noqa: E402
from streetpass_emu.friend_code import FriendCodeFileNotFound, load_friend_code  # noqa: E402
from streetpass_emu.keyslot_2e import KeyslotFileNotFound, load_streetpass_normal_key  # noqa: E402
from streetpass_emu.session import StreetPassResponder, generate_session_identity  # noqa: E402

from wifit3.device.manager import wlan_ifaces, wlan_close  # noqa: E402
from wifit3.errors import BringUpPermissionsError  # noqa: E402

sys.path.insert(0, str(_HERE))
from mii_plaza_editor import TmpBox  # noqa: E402

MII_PLAZA_SERVICE = bytes.fromhex("0002080000")  # docs/PROTOCOL_REFERENCE.md


class _StopRequested(Exception):
    pass


def _log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


class VerboseLogger:
    """live_streetpass_test.py のRawLogger相当(--verbose時のみ使う)。"""

    def __init__(self, our_mac: bytes):
        self.our_mac = our_mac
        self.known_peers: set = set()
        self.start = time.monotonic()

    def _t(self) -> str:
        return f"{time.monotonic() - self.start:6.2f}s"

    def on_rx(self, frame: bytes) -> None:
        if len(frame) < 24:
            return
        addr1, addr2 = frame[4:10], frame[10:16]
        involves_us = self.our_mac in (addr1, addr2)
        involves_known_peer = addr1 in self.known_peers or addr2 in self.known_peers
        # の野良キャプチャ(2026-09-15)の反省:
        # 以前はSSID空(=ワイルドカードプローブ)もStreetPassとみなしていたが、
        # これは周囲の普通のスマホ/PCのバックグラウンドスキャンでも大量に
        # ヒットしてしまい、実際の3DS検出との区別がつかなかった(街中歩行
        # テストで多数の無関係な機器のProbe Requestが誤って記録された)。
        # 本当のStreetPass判定は「SSIDが完全一致」または「Nintendo Vendor
        # Specific IEが実在する」の2つだけにする -- 後者ならconsole_id/
        # servicesを直接ログに出せるので、実際に3DSを見つけたかどうかが
        # 一目でわかる。
        nintendo_tag: Optional["dot11.NintendoTag"] = None
        is_streetpass_ssid = False
        try:
            probe = dot11.parse_probe_request(frame)
            is_streetpass_ssid = probe.ssid == dot11.STREETPASS_SSID.encode("ascii")
            nintendo_tag = dot11.find_nintendo_tag(probe.ies)
        except ValueError:
            try:
                resp = dot11.parse_probe_response(frame)
                is_streetpass_ssid = resp.ssid == dot11.STREETPASS_SSID.encode("ascii")
                nintendo_tag = dot11.find_nintendo_tag(resp.ies)
            except ValueError:
                pass
        is_streetpass = is_streetpass_ssid or nintendo_tag is not None
        if not (involves_us or involves_known_peer or is_streetpass):
            return
        fc = int.from_bytes(frame[0:2], "little")
        ftype, subtype = (fc >> 2) & 0x3, (fc >> 4) & 0xF
        extra = ""
        if nintendo_tag is not None:
            services_hex = [s.hex() for s in nintendo_tag.services]
            extra = f" NINTENDO console_id={nintendo_tag.console_id.hex()} services={services_hex} <== 3DS!"
        print(f"[{self._t()}] RX  fc={fc:#06x} (type={ftype} subtype={subtype}) "
              f"addr1={addr1.hex()} addr2={addr2.hex()} len={len(frame)}{extra}", flush=True)

    def note_peer(self, mac: bytes) -> None:
        self.known_peers.add(mac)

    def on_tx(self, frame: bytes, ok: bool, acked: bool = False) -> None:
        print(f"[{self._t()}] TX  ok={ok} acked={acked} len={len(frame)}", flush=True)


def _build_outbound_box(args: argparse.Namespace) -> tuple[bytes | None, int, object | None]:
    """--outbound-tmp-box-body-template から(必要ならmii_plaza_editorで
    ヘッダID/mii_idを再生成した)TMP Box bodyバイト列を作る。3つ目の
    戻り値は、--match-identity-to-mii用に取り出したMiiIdentity(無ければ
    None)。"""
    if args.outbound_tmp_box_body_template is None:
        return None, args.outbound_title_id, None

    box = TmpBox.load(args.outbound_tmp_box_body_template)
    if args.comment is not None:
        box.set_comment(args.comment)
    if args.fresh_each_cycle:
        box.randomize_ids()
        box.randomize_mii_id()
    box.recompute_hmac()

    mii_identity = None
    if args.match_identity_to_mii:
        try:
            mii_identity = box.get_mii_identity()
        except Exception as e:  # noqa: BLE001
            _log(f"警告: --match-identity-to-mii指定だがMii blobの復号に失敗: {e}")

    return bytes(box.data), args.outbound_title_id, mii_identity


async def _run_one_cycle(args: argparse.Namespace, cycle: int, out_dir: Path) -> dict:
    """1サイクル分(インターフェース起動→listen→停止)を実行し、結果の
    サマリdictを返す。"""
    result = {"peers": 0, "boxes_received": 0, "box_offered": False}

    ifaces = wlan_ifaces()
    if not ifaces:
        raise RuntimeError("no supported wifit3 interface found")
    iface = ifaces[0]

    try:
        ok = await iface.connect()
        if not ok:
            raise RuntimeError("interface connect() failed")
        await iface.set_channel(args.channel)

        try:
            keyslot_2e_key = load_streetpass_normal_key()
        except KeyslotFileNotFound as e:
            keyslot_2e_key = None
            # 調査結果の副産物: これが無いと
            # session._handle_data_frame()はCCMPデータフレームを受け取って
            # も一切ログを出さずサイレントにreturn []する(=実機には
            # 「確立はするが一切返信が来ない」ように見え、延々と再送→
            # タイムアウトする)。sudo env経由の起動では明示的に環境変数を
            # 渡し忘れやすいので、ここで必ず警告を出す。
            _log(f"cycle {cycle}: 警告 -- STREETPASS_KEYSLOT_2E_FILE未設定のため"
                 f"keyslot_2e_key=None ({e}) -- CCMPデータフレームを受信しても"
                 "復号・応答が一切できず、実機からは無反応に見えます")

        try:
            friend_code = load_friend_code()
        except FriendCodeFileNotFound as e:
            friend_code = None
            _log(f"cycle {cycle}: 警告 -- STREETPASS_FRIEND_CODE_FILE未設定のため"
                 f"friend_code=None ({e})")

        outbound_body, title_id, mii_identity = _build_outbound_box(args)
        outbound_message_box_entry = None
        outbound_tmp_box = None
        if outbound_body is not None:
            result["box_offered"] = True
            outbound_message_box_entry = spmtp.MessageBoxMetadataEntry(
                title_id=title_id, send_mode=0, flag=0, send_state=0,
                send_size=len(outbound_body), message_count=1,
            )
            outbound_tmp_box_header = spmtp.TmpBoxHeader(
                size=spmtp.TMP_BOX_HEADER_SIZE + len(outbound_body), title_id=title_id,
                group_id=0, message_count=1,
            )
            outbound_tmp_box = spmtp.build_tmp_box_header(outbound_tmp_box_header) + outbound_body

        if mii_identity is not None:
            # 調査結果の実験: WiFi層のtransferable_id/
            # original_macを、送信するMiiのauthor_id/deviceHashに一致させる
            extra: dict = {}
            if args.match_console_id_to_mii:
                seed = hashlib.sha256(mii_identity.author_id + mii_identity.mii_id).digest()
                derived_console_id = seed[0:8]
                derived_mac = bytearray(seed[8:14])
                derived_mac[0] = (derived_mac[0] | 0x02) & ~0x01  # locally administered, unicast
                extra["console_id"] = derived_console_id
                extra["mac"] = bytes(derived_mac)
            identity = generate_session_identity(
                transferable_id=mii_identity.author_id,
                original_mac=mii_identity.mii_id[4:10],
                **extra,
            )
            _log(f"cycle {cycle}: --match-identity-to-mii有効 -- "
                 f"transferable_id={mii_identity.author_id.hex()} "
                 f"original_mac={mii_identity.mii_id[4:10].hex()} "
                 f"(Mii: {mii_identity.nickname!r})")
            if args.match_console_id_to_mii:
                _log(f"cycle {cycle}: --match-console-id-to-mii有効 -- "
                     f"console_id={identity.console_id.hex()} mac={identity.mac.hex()} "
                     "(Miiのauthor_id+mii_idから導出)")
        else:
            identity = generate_session_identity()
        responder = StreetPassResponder(
            identity=identity, services=[MII_PLAZA_SERVICE], keyslot_2e_key=keyslot_2e_key,
            friend_code=friend_code, outbound_message_box_entry=outbound_message_box_entry,
            outbound_tmp_box=outbound_tmp_box,
        )
        _log(f"cycle {cycle}: identity mac={identity.mac.hex()} console_id={identity.console_id.hex()}")

        vlogger = VerboseLogger(identity.mac) if args.verbose else None
        if vlogger is not None:
            iface.register_rx_callback(lambda pkt: vlogger.on_rx(bytes(pkt.raw)))

        bridge = StreetPassDriverBridge(iface, responder, probe_interval_seconds=args.probe_interval_seconds)
        await bridge.start()
        await iface.enable_rx_acks()

        if vlogger is not None:
            _orig_send = iface.send_no_wait

            async def logged_send(frame_bytes: bytes) -> bool:
                result_ok = await _orig_send(frame_bytes)
                await asyncio.sleep(iface.driver.MAX_ACK_DELAY)
                vlogger.on_tx(frame_bytes, result_ok)
                return result_ok

            iface.send_no_wait = logged_send  # type: ignore[method-assign]

        # 転送が完了したら--cycle-secondsの満了を待たず短い猶予期間だけで
        # 切り上げる(相手からの最後のFIN/ACKを拾う程度の余裕は残す)。
        # まだ完了していなければ従来通りcycle_seconds全体を待つ。
        SEND_COMPLETE_GRACE_SECONDS = 10.0
        POLL_INTERVAL_SECONDS = 1.0
        elapsed = 0.0
        try:
            while elapsed < args.cycle_seconds:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                elapsed += POLL_INTERVAL_SECONDS
                if responder.outbound_send_completed():
                    _log(f"cycle {cycle}: 送信完了を検知、{SEND_COMPLETE_GRACE_SECONDS:.0f}秒の猶予後に切り上げ")
                    await asyncio.sleep(SEND_COMPLETE_GRACE_SECONDS)
                    break
        except asyncio.CancelledError:
            raise

        await bridge.stop()

        result["peers"] = len(responder.peers)
        for mac, state in responder.peers.items():
            _log(f"cycle {cycle}: peer {mac.hex()} -> {state.value}")

        for mac, tmp_boxes in responder.completed_tmp_boxes.items():
            for i, tmp_box in enumerate(tmp_boxes):
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                out_path = out_dir / f"tmp_box_{mac.hex()}_cycle{cycle}_{ts}_{i}.bin"
                out_path.write_bytes(tmp_box)
                result["boxes_received"] += 1
                _log(f"cycle {cycle}: received TMP Box from {mac.hex()} ({len(tmp_box)} bytes) -> {out_path}")

        return result
    finally:
        await wlan_close(ifaces)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--channel", type=int, default=1)
    parser.add_argument("--cycle-seconds", type=float, default=120,
                         help="1サイクルあたりの待ち受け時間(秒)")
    parser.add_argument("--cycles", type=int, default=0,
                         help="サイクル数の上限。0は無制限(Ctrl+Cで停止)")
    parser.add_argument("--sleep-between-cycles", type=float, default=2.0,
                         help="サイクル間のインターフェース再初期化待ち時間(秒)")
    parser.add_argument("--retry-backoff", type=float, default=5.0,
                         help="インターフェース起動失敗時の初回リトライ待ち時間(秒、以降指数バックオフ)")
    parser.add_argument("--max-retries", type=int, default=5,
                         help="1サイクルあたりのインターフェース起動リトライ上限")
    parser.add_argument("--outbound-tmp-box-body-template", type=Path, default=None,
                         help="提示するTMP Box bodyのテンプレートファイル(mii_plaza_editor.TmpBox形式)")
    parser.add_argument("--outbound-title-id", type=lambda s: int(s, 0), default=0x00020800)
    parser.add_argument("--comment", type=str, default=None,
                         help="毎サイクル、この文字列にコメント欄を書き換える(元と同じ文字数が必須)")
    parser.add_argument("--fresh-each-cycle", action="store_true",
                         help="サイクル毎にヘッダID(messageId等)と送信者Miiのmii_idを再生成する")
    parser.add_argument("--match-identity-to-mii", action="store_true",
                         help="調査結果の実験: WiFi層IdentityPacketの"
                              "transferable_id/original_macを、送信するTMP Boxの送信者Miiの"
                              "author_id/deviceHashに一致させる(--fresh-each-cycleと併用する場合、"
                              "再生成後のmii_idに追従する)")
    parser.add_argument("--match-console-id-to-mii", action="store_true",
                         help="調査結果のフォローアップ実験: --match-identity-to-mii"
                              "と併用し、継続スキャン層のconsole_id/mac(802.11層、"
                              "IdentityPacketのtransferable_id/original_macとは別物)も"
                              "送信者Miiのauthor_id/mii_idから決定論的に導出する"
                              "(SHA-256(author_id+mii_id)から生成。実機はhitするたびにこのペアを"
                              "ランダムに変えると観測されている=調査結果ため、"
                              "本来はMiiと無関係のはずだが未検証)")
    parser.add_argument("--probe-interval-seconds", type=float, default=None,
                         help="のプローバー役実験: これを指定すると、"
                              "受信応答オンリーだった従来の挙動に加えて、自分からもこの間隔で"
                              "Probe Requestをブロードキャストしにいく(実機の継続スキャンと同じ役)。"
                              "未指定(デフォルトNone)なら従来通りレスポンダー専用のまま")
    parser.add_argument("--out-dir", type=Path, default=Path("received_boxes"))
    parser.add_argument("--verbose", action="store_true", help="全フレームの生ログも出す")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    _log(f"streetpass_loop 開始 (channel={args.channel}, cycle={args.cycle_seconds}s, "
         f"cycles={'infinite' if args.cycles == 0 else args.cycles})")

    cycle = 0
    total_boxes = 0
    try:
        while args.cycles == 0 or cycle < args.cycles:
            cycle += 1
            attempt = 0
            while True:
                attempt += 1
                try:
                    result = await _run_one_cycle(args, cycle, args.out_dir)
                    total_boxes += result["boxes_received"]
                    break
                except (RuntimeError, BringUpPermissionsError) as e:
                    if attempt > args.max_retries:
                        _log(f"cycle {cycle}: 起動失敗が{args.max_retries}回続いたため諦める: {e}")
                        break
                    backoff = args.retry_backoff * (2 ** (attempt - 1))
                    _log(f"cycle {cycle}: インターフェース起動失敗(試行{attempt}): {e} -- {backoff:.0f}秒後に再試行")
                    await asyncio.sleep(backoff)

            await asyncio.sleep(args.sleep_between_cycles)
    except KeyboardInterrupt:
        _log("Ctrl+C received, stopping")

    _log(f"終了。合計{cycle}サイクル、受信TMP Box {total_boxes}件 -> {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

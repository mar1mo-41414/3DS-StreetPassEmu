"""Manual live test: run StreetPassResponder (session.py) against a real
wifit3-supported adapter and see whether a real nearby 3DS accepts our Probe
Response, follows up with the second, unicast Probe Request
(project findings step 4), and -- if a keyslot 0x2E key is configured -- actually decrypts its CCMP Data frames and
gets a real SPTCP SYN+ACK back.

Logs every RX frame involving our identity or a StreetPass-tagged peer (not
just the ones StreetPassResponder reacts to) plus every TX attempt and its
result, so a run that doesn't reach "established" still leaves something to
diagnose.

Usage (from the repo root, with tools/wifit3 set up -- see docs/EN/MONITOR_MODE.md):
    export STREETPASS_KEYSLOT_2E_FILE=/path/to/your/keyslot_2e.json  # optional, see keyslot_2e.py
    export STREETPASS_FRIEND_CODE_FILE=/path/to/your/friend_code.json  # optional, see friend_code.py
    cd tools/wifit3 && uv run python ../../scripts/live_streetpass_test.py --channel 1 --seconds 30

--outbound-tmp-box-body offers and, if the
peer wants it, actually sends a custom TMP Box -- this project's first
outbound Message/TMP Box content. The file's bytes become the TMP Box
*body* (i.e. everything after the 20-byte TmpBoxHeader this script builds
around it) verbatim, unexamined -- meant for testing what a real console
requires there, e.g. a real captured TMP Box's own body (see docs/
PROTOCOL.md §7.24's completed_tmp_boxes output) replayed as-is, or with
specific byte ranges you've deliberately zeroed/perturbed. Only bodies
that fit in one SPTCP transfer window (~0x38b8 bytes) are supported.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))

from streetpass_emu import dot11, spmtp  # noqa: E402
from streetpass_emu.driver_bridge import StreetPassDriverBridge  # noqa: E402
from streetpass_emu.friend_code import FriendCodeFileNotFound, load_friend_code  # noqa: E402
from streetpass_emu.keyslot_2e import KeyslotFileNotFound, load_streetpass_normal_key  # noqa: E402
from streetpass_emu.session import StreetPassResponder, generate_session_identity  # noqa: E402

from wifit3.device.manager import wlan_ifaces, wlan_close  # noqa: E402

MII_PLAZA_SERVICE = bytes.fromhex("0002080000")  # project findings


class RawLogger:
    """Logs every RX frame touching our identity or a StreetPass peer, and
    every TX attempt -- independent of whether StreetPassResponder reacts to
    it, so a silently-dropped or silently-failed frame is still visible."""

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
        is_streetpass = False
        try:
            probe = dot11.parse_probe_request(frame)
            is_streetpass = probe.ssid in (dot11.STREETPASS_SSID.encode("ascii"), b"")
        except ValueError:
            try:
                resp = dot11.parse_probe_response(frame)
                is_streetpass = resp.ssid in (dot11.STREETPASS_SSID.encode("ascii"), b"")
            except ValueError:
                pass
        if not (involves_us or involves_known_peer or is_streetpass):
            return
        fc = int.from_bytes(frame[0:2], "little")
        ftype, subtype = (fc >> 2) & 0x3, (fc >> 4) & 0xF
        print(f"[{self._t()}] RX  fc={fc:#06x} (type={ftype} subtype={subtype}) "
              f"addr1={addr1.hex()} addr2={addr2.hex()} len={len(frame)}")
        print(f"           {frame.hex()}")

    def note_peer(self, mac: bytes) -> None:
        self.known_peers.add(mac)

    def on_tx(self, frame: bytes, ok: bool, acked: bool = False) -> None:
        print(f"[{self._t()}] TX  ok={ok} acked={acked} len={len(frame)}")
        print(f"           {frame.hex()}")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument(
        "--outbound-tmp-box-body", type=Path, default=None,
        help="path to raw bytes to offer/send as our own outbound TMP Box's body",
    )
    parser.add_argument(
        "--outbound-title-id", type=lambda s: int(s, 0), default=0x00020800,
        help="title ID to offer the outbound TMP Box under (default: Mii Plaza, 0x00020800)",
    )
    args = parser.parse_args()

    ifaces = wlan_ifaces()
    if not ifaces:
        print("[-] no supported wifit3 interface found", file=sys.stderr)
        return 1
    iface = ifaces[0]
    print(f"[*] Bringing up {iface.description}...")

    ok = await iface.connect()
    if not ok:
        print("[-] connect failed", file=sys.stderr)
        return 1

    await iface.set_channel(args.channel)
    print(f"[*] Tuned to channel {args.channel}")

    try:
        keyslot_2e_key = load_streetpass_normal_key()
        print("[*] keyslot 0x2E key loaded -- CCMP decrypt/reply enabled")
    except KeyslotFileNotFound:
        keyslot_2e_key = None
        print("[*] no keyslot 0x2E key configured (STREETPASS_KEYSLOT_2E_FILE) -- "
              "handshake-detection only, no CCMP decrypt/reply")

    try:
        friend_code = load_friend_code()
        print("[*] friend code loaded -- disclosing a real one")
    except FriendCodeFileNotFound:
        friend_code = None
        print("[*] no friend code configured (STREETPASS_FRIEND_CODE_FILE) -- answering with 0")

    outbound_message_box_entry = None
    outbound_tmp_box = None
    if args.outbound_tmp_box_body is not None:
        body = args.outbound_tmp_box_body.read_bytes()
        outbound_message_box_entry = spmtp.MessageBoxMetadataEntry(
            title_id=args.outbound_title_id, send_mode=0, flag=0, send_state=0, send_size=len(body), message_count=1,
        )
        outbound_tmp_box_header = spmtp.TmpBoxHeader(
            size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=args.outbound_title_id, group_id=0, message_count=1,
        )
        outbound_tmp_box = spmtp.build_tmp_box_header(outbound_tmp_box_header) + body
        print(f"[*] outbound TMP Box loaded from {args.outbound_tmp_box_body} "
              f"({len(outbound_tmp_box)} bytes total, title_id={args.outbound_title_id:#x}) -- will offer it")

    identity = generate_session_identity()
    responder = StreetPassResponder(
        identity=identity, services=[MII_PLAZA_SERVICE], keyslot_2e_key=keyslot_2e_key, friend_code=friend_code,
        outbound_message_box_entry=outbound_message_box_entry, outbound_tmp_box=outbound_tmp_box,
    )
    print(f"[*] Our identity: mac={identity.mac.hex()} console_id={identity.console_id.hex()}")

    logger = RawLogger(identity.mac)

    def on_any_frame(packet) -> None:
        logger.on_rx(bytes(packet.raw))

    iface.register_rx_callback(on_any_frame)

    bridge = StreetPassDriverBridge(iface, responder)
    await bridge.start()

    await iface.enable_rx_acks()
    print(f"[*] RX-ACK tracking armed (FAKE_MAC={iface.driver.FAKE_MAC})")

    # Wrap send_no_wait so every TX attempt (not just successful ones) is logged,
    # along with whether the peer's hardware-ACK for it showed up on the RX tap.
    _orig_send = iface.send_no_wait

    async def logged_send(frame_bytes: bytes) -> bool:
        # acks_seen() is keyed by *our own* source MAC (Addr2 of the frame we
        # sent) -- an ACK's RA is the address of whoever is being acked, i.e. us.
        before = iface.acks_seen(identity.mac)
        result = await _orig_send(frame_bytes)
        await asyncio.sleep(iface.driver.MAX_ACK_DELAY)
        acked = iface.acks_seen(identity.mac) > before
        logger.on_tx(frame_bytes, result, acked=acked)
        try:
            resp = dot11.parse_probe_response(frame_bytes)
            logger.note_peer(resp.header.addr1)
        except ValueError:
            pass
        return result

    iface.send_no_wait = logged_send  # type: ignore[method-assign]

    print(f"[*] Listening for {args.seconds:.0f}s (Ctrl+C to stop early)...")

    try:
        await asyncio.sleep(args.seconds)
    except KeyboardInterrupt:
        pass

    await bridge.stop()
    await wlan_close(ifaces)

    print(f"[*] Peers seen by StreetPassResponder: {len(responder.peers)}")
    for mac, state in responder.peers.items():
        print(f"    {mac.hex()}: {state.value}")

    for mac, tmp_boxes in responder.completed_tmp_boxes.items():
        for i, tmp_box in enumerate(tmp_boxes):
            out_path = f"tmp_box_{mac.hex()}_{i}.bin"
            with open(out_path, "wb") as f:
                f.write(tmp_box)
            print(f"[*] TMP Box downloaded from {mac.hex()} ({len(tmp_box)} bytes) -- saved to {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
